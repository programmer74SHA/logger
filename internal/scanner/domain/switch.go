package domain

import (
	"fmt"
	"time"
)

// Cisco Error Codes
const (
	ErrCodeCiscoConnectionFailed    = "CONNECTION_FAILED"
	ErrCodeCiscoAuthFailed          = "AUTHENTICATION_FAILED"
	ErrCodeCiscoCommandFailed       = "COMMAND_FAILED"
	ErrCodeCiscoDataExtraction      = "DATA_EXTRACTION_FAILED"
	ErrCodeCiscoDataValidation      = "DATA_VALIDATION_FAILED"
	ErrCodeCiscoAssetCreation       = "ASSET_CREATION_FAILED"
	ErrCodeCiscoUnsupportedProtocol = "UNSUPPORTED_PROTOCOL"
	ErrCodeCiscoTimeoutError        = "TIMEOUT_ERROR"
	ErrCodeCiscoPrivilegeError      = "PRIVILEGE_ERROR"
)

// CiscoError represents Cisco-specific errors
type CiscoError struct {
	Code    string
	Message string
	Cause   error
}

func (e CiscoError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("cisco error [%s]: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("cisco error [%s]: %s", e.Code, e.Message)
}

// NewCiscoError creates a new Cisco error
func NewCiscoError(code, message string, cause error) *CiscoError {
	return &CiscoError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// CiscoScanResult represents the result of a Cisco device scan
type CiscoScanResult struct {
	AssetID           string              `json:"asset_id"`
	SystemInfo        CiscoSystemInfo     `json:"system_info"`
	Interfaces        []CiscoInterface    `json:"interfaces"`
	VLANs             []CiscoVLAN         `json:"vlans"`
	VLANPorts         []CiscoVLANPort     `json:"vlan_ports"`
	RoutingTable      []CiscoRoutingEntry `json:"routing_table"`
	Neighbors         []CiscoNeighbor     `json:"neighbors"`
	AssetsCreated     int                 `json:"assets_created"`
	ScanJobID         int64               `json:"scan_job_id"`
	DeviceIP          string              `json:"device_ip"`
	ConnectionMethod  string              `json:"connection_method"`
	ScanDuration      time.Duration       `json:"scan_duration"`
	ErrorsEncountered []string            `json:"errors_encountered"`
}

// CiscoInterface represents a network interface on a Cisco device
type CiscoInterface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IPAddress   string   `json:"ip_address"`
	SubnetMask  string   `json:"subnet_mask"`
	Status      string   `json:"status"`   // up/down/administratively down
	Protocol    string   `json:"protocol"` // up/down
	MacAddress  string   `json:"mac_address"`
	VLANs       []string `json:"vlans"` // VLANs associated with this interface
	AssetID     *string  `json:"asset_id,omitempty"`
}

// SetAssetID sets the asset ID for the interface
func (c *CiscoInterface) SetAssetID(assetID string) {
	c.AssetID = &assetID
}

// HasAsset checks if the interface has an associated asset
func (c *CiscoInterface) HasAsset() bool {
	return c.AssetID != nil && *c.AssetID != ""
}

// GetAssetID returns the asset ID if set
func (c *CiscoInterface) GetAssetID() string {
	if c.AssetID != nil {
		return *c.AssetID
	}
	return ""
}

// CiscoVLAN represents a VLAN configuration on a Cisco device
type CiscoVLAN struct {
	ID     int      `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"` // active/suspend/act_unsup
	Ports  []string `json:"ports"`  // Ports assigned to this VLAN
	Type   string   `json:"type"`   // enet/tr/fddi/trcrf/fddinet/trnet
	Parent int      `json:"parent"` // Parent VLAN for private VLANs
}

// CiscoVLANPort represents individual port assignments to VLANs
type CiscoVLANPort struct {
	ID         string `json:"id"`
	VlanID     int    `json:"vlan_id"`     // VLAN number
	VlanName   string `json:"vlan_name"`   // VLAN name for reference
	PortName   string `json:"port_name"`   // Port identifier (e.g., Fa0/1, Gi0/0/1)
	PortType   string `json:"port_type"`   // access, trunk, etc.
	PortStatus string `json:"port_status"` // active, inactive, etc.
}

// CiscoRoutingEntry represents a routing table entry
type CiscoRoutingEntry struct {
	Network       string `json:"network"`
	Mask          string `json:"mask"`
	NextHop       string `json:"next_hop"`
	Interface     string `json:"interface"`
	Metric        int    `json:"metric"`
	AdminDistance int    `json:"admin_distance"`
	Protocol      string `json:"protocol"` // connected/static/rip/ospf/eigrp/bgp
	Age           string `json:"age"`
	Tag           string `json:"tag"`
}

// CiscoNeighbor represents a CDP/LLDP neighbor
type CiscoNeighbor struct {
	DeviceID     string `json:"device_id"`
	LocalPort    string `json:"local_port"`
	RemotePort   string `json:"remote_port"`
	Platform     string `json:"platform"`
	IPAddress    string `json:"ip_address"`
	Capabilities string `json:"capabilities"`
	Software     string `json:"software"`
	Duplex       string `json:"duplex"`
	Protocol     string `json:"protocol"` // CDP/LLDP
}

// CiscoSystemInfo represents system information from the Cisco device
type CiscoSystemInfo struct {
	Hostname       string    `json:"hostname"`
	Model          string    `json:"model"`
	SystemUptime   string    `json:"system_uptime"`
	EthernetMAC    string    `json:"ethernet_mac"`
	ManagementIP   string    `json:"management_ip"`
	DomainName     string    `json:"domain_name"`
	Location       string    `json:"location"`
	LastConfigTime time.Time `json:"last_config_time"`
}
