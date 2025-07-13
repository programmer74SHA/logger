package cisco

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client represents a Cisco device client
type Client struct {
	config     ConnectConfig
	connection Connection
}

// ConnectConfig contains connection parameters
type ConnectConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	Timeout  time.Duration
}

// Connection represents a connection to a network device
type Connection interface {
	ExecuteInteractive(commands []string) (string, error)
	Close() error
}

// NewClientInsecure creates a new Cisco client with insecure SSH settings
func NewClientInsecure(config ConnectConfig) *Client {
	return &Client{
		config: config,
	}
}

// Connect establishes connection to the Cisco device
func (c *Client) Connect(ctx context.Context) error {
	connector := NewSSHConnector()
	connection, err := connector.Connect(ctx, c.config)
	if err != nil {
		return fmt.Errorf("failed to connect to Cisco device: %w", err)
	}
	c.connection = connection
	return nil
}

// ExecuteCommands executes commands on the device and returns raw output
func (c *Client) ExecuteCommands(ctx context.Context, commands []string) (string, error) {
	if c.connection == nil {
		return "", fmt.Errorf("not connected to device")
	}

	executor := NewCiscoCommandExecutor()
	return executor.ExecuteCommands(ctx, c.connection, commands)
}

// ParseOutput parses raw command output into structured data
func (c *Client) ParseOutput(output string) (*CiscoScanResult, error) {
	parser := NewCiscoOutputParser()
	result := &CiscoScanResult{
		DeviceIP:         c.config.Host,
		ConnectionMethod: "SSH",
	}

	if err := parser.ParseOutput(output, result); err != nil {
		return nil, fmt.Errorf("failed to parse output: %w", err)
	}

	return result, nil
}

// Close closes the connection
func (c *Client) Close() error {
	if c.connection != nil {
		return c.connection.Close()
	}
	return nil
}

// GetDefaultCommands returns default command set for Cisco devices
func (c *Client) GetDefaultCommands() []string {
	return []string{
		"terminal length 0",         // Disable pagination
		"show version",              // System information
		"show interfaces",           // Interface details
		"show vlan brief",           // VLAN information
		"show cdp neighbors detail", // CDP neighbors
		"show ip route",             // Routing table
	}
}

// CiscoConnector handles SSH connections to Cisco devices
type CiscoConnector interface {
	Connect(ctx context.Context, config ConnectConfig) (Connection, error)
}

// SSHConnector implements SSH connections
type SSHConnector struct{}

// NewSSHConnector creates a new SSH connector
func NewSSHConnector() *SSHConnector {
	return &SSHConnector{}
}

// Connect establishes SSH connection
func (c *SSHConnector) Connect(ctx context.Context, config ConnectConfig) (Connection, error) {
	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         config.Timeout,
	}

	conn, err := ssh.Dial("tcp", net.JoinHostPort(config.Host, config.Port), sshConfig)
	if err != nil {
		return nil, fmt.Errorf("SSH dial failed: %w", err)
	}

	return &SSHConnection{client: conn}, nil
}

// SSHConnection wraps SSH client with interactive session support
type SSHConnection struct {
	client *ssh.Client
}

// ExecuteInteractive runs multiple commands in an interactive shell session
func (c *SSHConnection) ExecuteInteractive(commands []string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up pipes for interactive communication
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	// Start shell
	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("failed to start shell: %w", err)
	}

	// Wait a moment for shell to be ready
	time.Sleep(2 * time.Second)

	// Execute commands with logging
	for i, cmd := range commands {
		if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
			continue
		}

		// Give more time for each command to execute
		if i == 0 {
			// First command (terminal length 0) needs less time
			time.Sleep(1 * time.Second)
		} else {
			// Other commands may need more time
			time.Sleep(3 * time.Second)
		}
	}

	// Exit gracefully
	stdin.Write([]byte("exit\n"))
	stdin.Close()

	// Read all output with timeout
	var outputBuffer strings.Builder
	buffer := make([]byte, 8192) // Larger buffer

	// Wait for session to complete with timeout
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	// Read output with timeout
	go func() {
		for {
			n, err := stdout.Read(buffer)
			if n > 0 {
				outputBuffer.Write(buffer[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// Wait for session completion or timeout
	select {
	case err := <-done:
		if err != nil {
			// Session completed with error (this is normal for exit command)
		}
	case <-time.After(30 * time.Second):
		session.Close()
	}

	output := outputBuffer.String()
	return output, nil
}

// Close closes the SSH connection
func (c *SSHConnection) Close() error {
	return c.client.Close()
}

// CommandExecutor handles command execution on devices
type CommandExecutor interface {
	ExecuteCommands(ctx context.Context, conn Connection, commands []string) (string, error)
}

// CiscoCommandExecutor executes Cisco IOS commands
type CiscoCommandExecutor struct{}

// NewCiscoCommandExecutor creates a new command executor
func NewCiscoCommandExecutor() *CiscoCommandExecutor {
	return &CiscoCommandExecutor{}
}

// ExecuteCommands executes a list of commands using interactive session for Cisco devices
func (e *CiscoCommandExecutor) ExecuteCommands(ctx context.Context, conn Connection, commands []string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	// Use interactive session for Cisco devices
	output, err := conn.ExecuteInteractive(commands)
	if err != nil {
		return "", fmt.Errorf("interactive command execution failed: %w", err)
	}

	return output, nil
}

// OutputParser handles parsing of command output
type OutputParser interface {
	ParseOutput(output string, result *CiscoScanResult) error
}

// CiscoOutputParser parses Cisco IOS command output
type CiscoOutputParser struct{}

// NewCiscoOutputParser creates a new output parser
func NewCiscoOutputParser() *CiscoOutputParser {
	return &CiscoOutputParser{}
}

// ParseOutput parses the raw command output into structured data
func (p *CiscoOutputParser) ParseOutput(output string, result *CiscoScanResult) error {
	result.SystemInfo = p.parseSystemInfo(output)
	result.Interfaces = p.parseInterfaces(output)
	result.VLANs, result.VLANPorts = p.parseVLANs(output)
	result.Neighbors = p.parseNeighbors(output)
	result.RoutingTable = p.parseRoutes(output)

	return nil
}

// parseSystemInfo extracts system information
func (p *CiscoOutputParser) parseSystemInfo(output string) CiscoSystemInfo {
	sysInfo := CiscoSystemInfo{}

	patterns := map[string]*regexp.Regexp{
		"hostname": regexp.MustCompile(`(?m)^(\S+)[>#]`),
		"model":    regexp.MustCompile(`(?i)cisco\s+(\S+)`),
		"uptime":   regexp.MustCompile(`(?i)uptime\s+is\s+([^\n\r]+)`),
	}

	if match := patterns["hostname"].FindStringSubmatch(output); len(match) > 1 {
		sysInfo.Hostname = match[1]
	}
	if match := patterns["model"].FindStringSubmatch(output); len(match) > 1 {
		sysInfo.Model = match[1]
	}
	if match := patterns["uptime"].FindStringSubmatch(output); len(match) > 1 {
		sysInfo.SystemUptime = strings.TrimSpace(match[1])
	}

	return sysInfo
}

// parseInterfaces extracts interface information
func (p *CiscoOutputParser) parseInterfaces(output string) []CiscoInterface {
	var interfaces []CiscoInterface

	interfaceRegex := regexp.MustCompile(`(GigabitEthernet\d+/\d+|FastEthernet\d+/\d+|Ethernet\d+/\d+|Vlan\d+) is (up|down|administratively down)`)
	protocolRegex := regexp.MustCompile(`line protocol is (up|down)`)
	ipRegex := regexp.MustCompile(`Internet address is (\d+\.\d+\.\d+\.\d+)/(\d+)`)
	macRegex := regexp.MustCompile(`Hardware is.*address is ([a-fA-F0-9.:]+)`)

	sections := p.splitIntoSections(output, interfaceRegex)

	for _, section := range sections {
		if matches := interfaceRegex.FindStringSubmatch(section); len(matches) >= 3 {
			iface := CiscoInterface{
				Name:   matches[1],
				Status: matches[2],
			}

			if protocolMatch := protocolRegex.FindStringSubmatch(section); len(protocolMatch) > 1 {
				iface.Protocol = protocolMatch[1]
			}
			if ipMatch := ipRegex.FindStringSubmatch(section); len(ipMatch) > 2 {
				iface.IPAddress = ipMatch[1]
				cidr, _ := strconv.Atoi(ipMatch[2])
				iface.SubnetMask = cidrToSubnetMask(cidr)
			}
			if macMatch := macRegex.FindStringSubmatch(section); len(macMatch) > 1 {
				iface.MacAddress = macMatch[1]
			}

			interfaces = append(interfaces, iface)
		}
	}

	return interfaces
}

func (p *CiscoOutputParser) parseVLANs(output string) ([]CiscoVLAN, []CiscoVLANPort) {
	var vlans []CiscoVLAN
	var vlanPorts []CiscoVLANPort

	// Split output into lines for processing
	lines := strings.Split(output, "\n")

	// Find the start of VLAN table (look for header)
	vlanTableStart := -1
	for i, line := range lines {
		if strings.Contains(line, "VLAN Name") && strings.Contains(line, "Status") {
			vlanTableStart = i + 1 // Skip the header line
			break
		}
	}

	if vlanTableStart == -1 {
		return vlans, vlanPorts
	}

	// Process VLAN entries
	for i := vlanTableStart; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Skip separator lines
		if strings.Contains(line, "----") {
			continue
		}

		// Check if this is a VLAN entry (starts with a number)
		vlanRegex := regexp.MustCompile(`^(\d+)\s+(\S+)\s+(active|suspended|act/unsup)\s*(.*)`)
		match := vlanRegex.FindStringSubmatch(line)

		if len(match) >= 4 {
			vlanID, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}

			vlan := CiscoVLAN{
				ID:     vlanID,
				Name:   match[2],
				Status: match[3],
				Type:   "enet",
			}

			// Collect all ports for this VLAN (may span multiple lines)
			allPorts := []string{}
			portsStr := strings.TrimSpace(match[4])

			// Add ports from the current line
			if portsStr != "" && portsStr != "unassigned" {
				ports := strings.Fields(portsStr)
				allPorts = append(allPorts, ports...)
			}

			// Check subsequent lines for continuation of ports
			for j := i + 1; j < len(lines); j++ {
				nextLine := strings.TrimSpace(lines[j])
				if nextLine == "" {
					break
				}

				// If next line starts with a number, it's a new VLAN
				if regexp.MustCompile(`^\d+\s`).MatchString(nextLine) {
					break
				}

				// If the line contains only port names (no VLAN ID), it's a continuation
				portContinuationRegex := regexp.MustCompile(`^[A-Za-z]\w*[\d/,\s]+`)
				if portContinuationRegex.MatchString(nextLine) {
					continuationPorts := strings.Fields(nextLine)
					allPorts = append(allPorts, continuationPorts...)
					i = j // Skip this line in the main loop
				} else {
					break
				}
			}

			// Store ports in VLAN object for backward compatibility
			vlan.Ports = allPorts

			// Create individual VLAN port records
			for _, portName := range allPorts {
				portName = strings.TrimSpace(portName)
				if portName != "" && portName != "unassigned" {
					// Try to determine port type from name
					portType := "access" // default
					if strings.Contains(strings.ToLower(portName), "trunk") {
						portType = "trunk"
					}

					vlanPort := CiscoVLANPort{
						VlanID:     vlanID,
						VlanName:   match[2],
						PortName:   portName,
						PortType:   portType,
						PortStatus: "active", // Default status
					}
					vlanPorts = append(vlanPorts, vlanPort)
				}
			}

			vlans = append(vlans, vlan)
		}
	}

	return vlans, vlanPorts
}

// parseNeighbors extracts neighbor information
func (p *CiscoOutputParser) parseNeighbors(output string) []CiscoNeighbor {
	var neighbors []CiscoNeighbor

	deviceRegex := regexp.MustCompile(`Device ID:\s*([^\n]+)`)
	sections := p.splitIntoSections(output, deviceRegex)

	for _, section := range sections {
		if deviceMatch := deviceRegex.FindStringSubmatch(section); len(deviceMatch) > 1 {
			neighbor := CiscoNeighbor{
				DeviceID: strings.TrimSpace(deviceMatch[1]),
				Protocol: "CDP",
			}

			patterns := map[string]*regexp.Regexp{
				"platform": regexp.MustCompile(`Platform:\s*([^,\n]+)`),
				"local":    regexp.MustCompile(`Interface:\s*([^,\n]+)`),
				"remote":   regexp.MustCompile(`Port ID \(outgoing port\):\s*([^\n]+)`),
				"ip":       regexp.MustCompile(`IP address:\s*(\d+\.\d+\.\d+\.\d+)`),
			}

			if match := patterns["platform"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.Platform = strings.TrimSpace(match[1])
			}
			if match := patterns["local"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.LocalPort = strings.TrimSpace(match[1])
			}
			if match := patterns["remote"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.RemotePort = strings.TrimSpace(match[1])
			}
			if match := patterns["ip"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.IPAddress = match[1]
			}

			neighbors = append(neighbors, neighbor)
		}
	}

	return neighbors
}

// parseRoutes extracts routing information
func (p *CiscoOutputParser) parseRoutes(output string) []CiscoRoutingEntry {
	var routes []CiscoRoutingEntry

	routeRegex := regexp.MustCompile(`(?m)^([CSOEIBD*])\s+(\d+\.\d+\.\d+\.\d+/\d+|\d+\.\d+\.\d+\.\d+)\s+.*?via\s+(\d+\.\d+\.\d+\.\d+).*?(\S+)$`)
	matches := routeRegex.FindAllStringSubmatch(output, -1)

	protocolMap := map[string]string{
		"C": "connected", "S": "static", "O": "ospf", "E": "eigrp",
		"I": "igrp", "B": "bgp", "D": "eigrp", "*": "candidate_default",
	}

	for _, match := range matches {
		if len(match) >= 5 {
			protocol := "unknown"
			if mapped, exists := protocolMap[match[1]]; exists {
				protocol = mapped
			}

			route := CiscoRoutingEntry{
				Protocol:  protocol,
				Network:   match[2],
				NextHop:   match[3],
				Interface: match[4],
			}

			routes = append(routes, route)
		}
	}

	return routes
}

// splitIntoSections splits output into sections based on regex pattern
func (p *CiscoOutputParser) splitIntoSections(output string, pattern *regexp.Regexp) []string {
	matches := pattern.FindAllStringIndex(output, -1)
	if len(matches) == 0 {
		return []string{output}
	}

	var sections []string
	for i, match := range matches {
		start := match[0]
		var end int
		if i+1 < len(matches) {
			end = matches[i+1][0]
		} else {
			end = len(output)
		}
		sections = append(sections, output[start:end])
	}

	return sections
}

// cidrToSubnetMask converts CIDR notation to subnet mask
func cidrToSubnetMask(cidr int) string {
	if cidr < 0 || cidr > 32 {
		return ""
	}

	mask := (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xFF,
		(mask>>16)&0xFF,
		(mask>>8)&0xFF,
		mask&0xFF)
}
