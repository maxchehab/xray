package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mitchellh/go-ps"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	clientPort int
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	clientPort     int
}

type Response struct {
	Headers    map[string]string `json:"headers"`
	StatusCode int               `json:"statusCode"`
	Status     string            `json:"status"`
	Body       string            `json:"body"`
}

type Request struct {
	Headers map[string]string `json:"headers"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   url.Values        `json:"query"`
	Body    string            `json:"body"`
}

type Process struct {
	PID  uint
	Port int
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:        net,
		transport:  transport,
		r:          tcpreader.NewReaderStream(),
		clientPort: h.clientPort,
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func flattenHeaders(headers map[string][]string) map[string]string {
	h := make(map[string]string)

	for k, v := range headers {
		h[k] = strings.Join(v, ", ")
	}

	return h
}

func printResponse(res *http.Response) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(res.Body)
	body := buf.String()

	response := &Response{
		flattenHeaders(res.Header),
		res.StatusCode,
		res.Status,
		body,
	}

	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(b))
}

func printRequest(req *http.Request) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	body := buf.String()

	request := &Request{
		flattenHeaders(req.Header),
		req.Method,
		req.URL.RawPath,
		req.URL.Query(),
		body,
	}

	b, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(b))
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)

	if h.transport.Dst().String() == strconv.Itoa(h.clientPort) {
		for {
			req, err := http.ReadRequest(buf)

			if err == io.EOF {
				return
			} else if err != nil {
				log.Fatal("Error reading stream", h.transport, ":", err)
			} else {
				printRequest(req)
			}
		}
	} else {
		for {
			res, err := http.ReadResponse(buf, nil)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			} else if err != nil {
				log.Fatal("Error reading stream", h.transport, ":", err)
			} else {
				printResponse(res)
			}
		}
	}

}

func parseProcessLines(lines []string) (Process, error) {
	p := Process{}
	var portRegex = regexp.MustCompile(`(\d+)$`)
	for _, line := range lines {

		if line[0] == 'p' {
			pid, err := strconv.Atoi(line[1:])
			if err != nil {
				return p, err
			}

			p.PID = uint(pid)
		}

		if line[0] == 'n' {
			parsedPort := portRegex.FindString(line)
			if parsedPort == "" {
				continue
			}

			port, err := strconv.Atoi(parsedPort)
			if err != nil {
				return p, err
			}

			p.Port = port
		}

		if p.Port != 0 && p.PID != 0 {
			break
		}
	}
	return p, nil
}

func parseAppendProcessLines(processes []Process, linesChunk []string) ([]Process, []string, error) {
	if len(linesChunk) == 0 {
		return processes, linesChunk, nil
	}
	process, err := parseProcessLines(linesChunk)
	if err != nil {
		return processes, linesChunk, err
	}
	processesAfter := append(processes, process)
	linesChunkAfter := []string{}
	return processesAfter, linesChunkAfter, nil
}

func parseLSOF(s string) ([]Process, error) {
	lines := strings.Split(s, "\n")
	linesChunk := []string{}
	processes := []Process{}
	var err error
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// End of process, let's parse those lines
		if strings.HasPrefix(line, "p") && len(linesChunk) > 0 {
			processes, linesChunk, err = parseAppendProcessLines(processes, linesChunk)
			if err != nil {
				return nil, err
			}
		}
		linesChunk = append(linesChunk, line)
	}
	processes, _, err = parseAppendProcessLines(processes, linesChunk)
	if err != nil {
		return nil, err
	}
	return processes, nil
}

func findPortAndPID(pid uint) (int, uint) {
	output, err := exec.Command("lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-Fnp").Output()
	if err != nil {
		log.Panicf("Failed to run lsof -iTCP -sTCP:LISTEN -P -Fnp %v", err)
	}

	procs, err := parseLSOF(string(output))
	if err != nil {
		log.Panicf("Failed to parse processes %v", err)
	}

	for _, proc := range procs {
		if proc.PID == pid || isChildProc(proc.PID, pid) {
			return proc.Port, proc.PID
		}
	}

	return -1, 0
}

func isChildProc(pid uint, ppid uint) bool {
	proc, err := ps.FindProcess(int(pid))
	if err != nil || proc == nil || proc.Pid() == 0 {
		return false
	}

	parentProc := uint(proc.PPid())

	if parentProc == ppid {
		return true
	}

	return isChildProc(parentProc, ppid)
}

func executeCommand(args []string, portChan chan int, quitChan chan bool) {
	command := exec.Command(args[0], args[1:]...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Start()
	var portPID uint = 0

	defer func() {
		fmt.Println("Killing command")
		pgid, err := syscall.Getpgid(command.Process.Pid)

		if err == nil {
			syscall.Kill(-pgid, 15)       // note the minus sign
			syscall.Kill(int(portPID), 9) // note the minus sign
		}

		command.Wait()
	}()

	fmt.Println("Executing command,", strings.Join(args, " "))

	var port int = -1

	for port == -1 {
		port, portPID = findPortAndPID(uint(command.Process.Pid))
	}

	portChan <- port

	for {
		select {
		case <-quitChan:
			fmt.Println("Killing command")
			pgid, err := syscall.Getpgid(command.Process.Pid)

			if err == nil {
				syscall.Kill(-pgid, 15)       // note the minus sign
				syscall.Kill(int(portPID), 9) // note the minus sign
			}

			command.Wait()
			return
		}
	}
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	portChan := make(chan int)
	quitChan := make(chan bool)
	defer func() {
		quitChan <- true
	}()

	go executeCommand(os.Args[1:], portChan, quitChan)
	port := <-portChan

	fmt.Println("listening on port", port)

	handle, err = pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(fmt.Sprintf("tcp and port %d", port)); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{port}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
