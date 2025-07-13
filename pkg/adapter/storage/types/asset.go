package types

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// Base tables (no dependencies)
type Vendors struct {
	ID         uint      `gorm:"primaryKey;autoIncrement"`
	VendorName string    `gorm:"size:100;uniqueIndex;not null"`
	VendorCode string    `gorm:"size:20;uniqueIndex;not null"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`

	// Relationships
	Assets []Assets `gorm:"foreignKey:VendorID"`
}

func (Vendors) TableName() string {
	return "vendors"
}

type InterfaceTypes struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TypeName    string `gorm:"size:50;uniqueIndex;not null"`
	Description string `gorm:"size:255"`

	// Relationships
	Interfaces []Interfaces `gorm:"foreignKey:InterfaceTypeID"`
}

func (InterfaceTypes) TableName() string {
	return "interface_types"
}

// Assets table (depends on vendors)
type Assets struct {
	ID               string     `gorm:"column:id;size:50;primaryKey"`
	VendorID         uint       `gorm:"not null;index"`
	Name             string     `gorm:"size:255"`
	Domain           string     `gorm:"size:255"`
	Hostname         string     `gorm:"size:255"`
	OSName           string     `gorm:"size:100;column:os_name"`
	OSVersion        string     `gorm:"size:100;column:os_version"`
	Description      string     `gorm:"type:text"`
	AssetType        string     `gorm:"size:50;default:'firewall';column:asset_type"`
	DiscoveredBy     *string    `gorm:"column:discovered_by;size:255"`
	Risk             string     `gorm:"type:enum('low','medium','high','critical');default:'medium'"`
	LoggingCompleted bool       `gorm:"default:false;column:logging_completed"`
	AssetValue       float64    `gorm:"type:decimal(15,2);default:0.00;column:asset_value"`
	CreatedAt        time.Time  `gorm:"autoCreateTime;column:created_at"`
	UpdatedAt        time.Time  `gorm:"autoUpdateTime;column:updated_at"`
	DeletedAt        *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Vendor          Vendors           `gorm:"foreignKey:VendorID"`
	FirewallDetails []FirewallDetails `gorm:"foreignKey:AssetID"`
	IPs             []IPs             `gorm:"foreignKey:AssetID"`
	AssetScanJobs   []AssetScanJob    `gorm:"foreignKey:AssetID"`
	Ports           []Port            `gorm:"foreignKey:AssetID"`
	VMwareVMs       []VMwareVM        `gorm:"foreignKey:AssetID"`
	Interfaces      []Interfaces      `gorm:"foreignKey:AssetID"`
	VLANs           []VLANs           `gorm:"foreignKey:AssetID"`
}

func (Assets) TableName() string {
	return "assets"
}

// Firewall details (depends on assets)
type FirewallDetails struct {
	ID              string `gorm:"column:id;size:50;primaryKey"`
	AssetID         string `gorm:"not null;uniqueIndex"`
	Model           string `gorm:"size:100"`
	FirmwareVersion string `gorm:"size:100"`
	SerialNumber    string `gorm:"size:100"`
	IsHAEnabled     bool   `gorm:"default:false"`
	HARole          string `gorm:"type:enum('active','passive','standalone');default:'standalone'"`
	ManagementIP    string `gorm:"size:45;not null"`
	SiteName        string `gorm:"size:255"`
	Location        string `gorm:"size:255"`
	Status          string `gorm:"type:enum('active','inactive','maintenance');default:'active'"`
	LastSync        *time.Time
	SyncStatus      string     `gorm:"type:enum('success','failed','pending');default:'pending'"`
	CreatedAt       time.Time  `gorm:"autoCreateTime"`
	UpdatedAt       time.Time  `gorm:"autoUpdateTime"`
	DeletedAt       *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Asset    Assets           `gorm:"foreignKey:AssetID"`
	Policies []FirewallPolicy `gorm:"foreignKey:FirewallDetailsID"`
}

func (FirewallDetails) TableName() string {
	return "firewall_details"
}

// Zones table (depends on firewall_details)
type Zones struct {
	ID                    string     `gorm:"column:id;size:50;primaryKey"`
	ZoneName              string     `gorm:"size:100;not null;uniqueIndex"`
	ZoneType              string     `gorm:"type:enum('security','virtual_router','context','vdom','vsys');default:'security'"`
	VendorZoneType        string     `gorm:"size:50"`
	Description           string     `gorm:"type:text"`
	ZoneMode              string     `gorm:"type:enum('layer3','layer2','virtual-wire','tap');default:'layer3'"`
	IntrazoneAction       string     `gorm:"type:enum('allow','deny');default:'allow'"`
	ZoneProtectionProfile string     `gorm:"size:100"`
	LogSetting            string     `gorm:"size:100"`
	CreatedAt             time.Time  `gorm:"autoCreateTime"`
	UpdatedAt             time.Time  `gorm:"autoUpdateTime"`
	DeletedAt             *time.Time `gorm:"index;column:deleted_at"`
	FirewallID            string     `gorm:"size:255;not null"`

	// Relationships
	FirewallDetails FirewallDetails  `gorm:"foreignKey:FirewallID"`
	ZoneDetails     []ZoneDetails    `gorm:"foreignKey:ZoneID"`
	SrcPolicies     []FirewallPolicy `gorm:"foreignKey:SrcZoneID"`
	DstPolicies     []FirewallPolicy `gorm:"foreignKey:DstZoneID"`
}

func (Zones) TableName() string {
	return "zones"
}

// Interfaces table (depends on interface_types and assets, has self-reference)
type Interfaces struct {
	ID                   string     `gorm:"column:id;size:50;primaryKey"`
	InterfaceName        string     `gorm:"size:100;not null;uniqueIndex"`
	InterfaceTypeID      uint       `gorm:"not null;index"`
	AssetID              *string    `gorm:"size:50;index"`
	VirtualRouter        string     `gorm:"size:100"`
	VirtualSystem        string     `gorm:"size:100"`
	Description          string     `gorm:"type:text"`
	OperationalStatus    string     `gorm:"type:enum('up','down','unknown');default:'unknown'"`
	AdminStatus          string     `gorm:"type:enum('up','down');default:'up'"`
	ParentInterfaceID    *string    `gorm:"size:50;index"` // Self-reference for sub-interfaces
	VLANId               *int       `gorm:"column:vlan_id"`
	MacAddress           string     `gorm:"size:17"`
	VendorSpecificConfig string     `gorm:"type:json"`
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
	DeletedAt            *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Asset           *Assets         `gorm:"foreignKey:AssetID"`
	InterfaceType   InterfaceTypes  `gorm:"foreignKey:InterfaceTypeID"`
	ParentInterface *Interfaces     `gorm:"foreignKey:ParentInterfaceID"` // Self-reference
	SubInterfaces   []Interfaces    `gorm:"foreignKey:ParentInterfaceID"`
	IPs             []IPs           `gorm:"foreignKey:InterfaceID"`
	ZoneDetails     []ZoneDetails   `gorm:"foreignKey:FirewallInterfaceID"`
	VLANInterfaces  []VLANInterface `gorm:"foreignKey:InterfaceID"`
}

func (Interfaces) TableName() string {
	return "interfaces"
}

// VLANs table (depends on assets)
type VLANs struct {
	ID                   string     `gorm:"column:id;size:50;primaryKey"`
	VLANNumber           int        `gorm:"not null;column:vlan_id"`
	VLANName             string     `gorm:"size:100"`
	Description          string     `gorm:"type:text"`
	IsNative             bool       `gorm:"default:false"`
	VendorSpecificConfig string     `gorm:"type:json"`
	DeviceType           string     `gorm:"size:255;not null"`
	AssetID              string     `gorm:"size:50;not null"`
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
	DeletedAt            *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Asset       Assets        `gorm:"foreignKey:AssetID"`
	ZoneDetails []ZoneDetails `gorm:"foreignKey:VLANTableID"`
}

func (VLANs) TableName() string {
	return "vlans"
}

// IPs table (depends on assets and interfaces)
type IPs struct {
	ID          string     `gorm:"column:id;size:50;primaryKey"`
	AssetID     string     `gorm:"not null;index"`
	InterfaceID *string    `gorm:"index"` // Made optional for management IPs
	IPAddress   string     `gorm:"size:45;not null;column:ip_address"`
	MacAddress  string     `gorm:"size:17;column:mac_address"`
	CIDRPrefix  *int       `gorm:"column:cidr_prefix"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   *time.Time `gorm:"autoUpdateTime"`
	DeletedAt   *time.Time `gorm:"index"`

	// Relationships
	Asset     Assets      `gorm:"foreignKey:AssetID"`
	Interface *Interfaces `gorm:"foreignKey:InterfaceID"`
}

func (IPs) TableName() string {
	return "ips"
}

// VLANInterface junction table
type VLANInterface struct {
	ID          uint       `gorm:"primaryKey;autoIncrement"`
	VLANTableID string     `gorm:"size:50;not null;index;column:vlan_table_id"` // References vlans.id (primary key)
	InterfaceID string     `gorm:"size:50;not null;index"`                      // References interfaces.id
	IsNative    *bool      `gorm:""`
	CreatedAt   *time.Time `gorm:""`
	DeletedAt   *time.Time `gorm:"index;column:deleted_at"`

	// Relationships - VLANTableID references vlans.id (primary key)
	VLAN      VLANs      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:VLANTableID;references:ID"`
	Interface Interfaces `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:InterfaceID;references:ID"`
}

func (VLANInterface) TableName() string {
	return "vlan_interface"
}

// Zone details (junction table - depends on zones, interfaces, and vlans)
type ZoneDetails struct {
	ID                  string     `gorm:"column:id;size:50;primaryKey"`
	ZoneID              string     `gorm:"not null;index"`
	FirewallInterfaceID string     `gorm:"not null;index;column:firewall_interface_id"`
	VLANTableID         string     `gorm:"not null;index;column:vlan_table_id"` // References vlans.id
	CreatedAt           time.Time  `gorm:"autoCreateTime"`
	UpdatedAt           time.Time  `gorm:"autoUpdateTime"`
	DeletedAt           *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Zone      Zones      `gorm:"foreignKey:ZoneID"`
	Interface Interfaces `gorm:"foreignKey:FirewallInterfaceID"`
	VLAN      VLANs      `gorm:"foreignKey:VLANTableID;references:ID"` // References vlans.id
}

func (ZoneDetails) TableName() string {
	return "zone_details"
}

// Firewall policies (depends on firewall_details and zones)
type FirewallPolicy struct {
	ID                   string     `gorm:"column:id;size:50;primaryKey"`
	FirewallDetailsID    string     `gorm:"not null;index"`
	PolicyName           string     `gorm:"size:255"`
	PolicyID             *int       `gorm:"index"`
	SrcZoneID            *string    `gorm:"index"`
	DstZoneID            *string    `gorm:"index"`
	Action               string     `gorm:"type:enum('allow','deny','drop','reject','tunnel');default:'deny'"`
	PolicyType           string     `gorm:"type:enum('security','nat','qos','decryption');default:'security'"`
	Status               string     `gorm:"type:enum('enabled','disabled');default:'enabled'"`
	RuleOrder            *int       `gorm:"index"`
	VendorSpecificConfig string     `gorm:"type:json"`
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
	DeletedAt            *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	FirewallDetails FirewallDetails `gorm:"foreignKey:FirewallDetailsID"`
	SrcZone         *Zones          `gorm:"foreignKey:SrcZoneID"`
	DstZone         *Zones          `gorm:"foreignKey:DstZoneID"`
}

func (FirewallPolicy) TableName() string {
	return "firewall_policy"
}

// Keep your existing Port and VMwareVM types...
type Port struct {
	ID             string     `gorm:"column:id;size:50;primaryKey"`
	AssetID        string     `gorm:"column:asset_id;not null"`
	PortNumber     int        `gorm:"column:port_number;not null"`
	Protocol       string     `gorm:"column:protocol;type:enum('TCP','UDP');not null"`
	State          string     `gorm:"column:state;type:enum('Up','Down','Unknown');not null"`
	ServiceName    *string    `gorm:"column:service_name;size:100"`
	ServiceVersion *string    `gorm:"column:service_version;size:100"`
	Description    *string    `gorm:"column:description;size:500"`
	DiscoveredAt   time.Time  `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt      *time.Time `gorm:"column:deleted_at;type:datetime"`

	Asset Assets `gorm:"foreignKey:AssetID"`
}

func (Port) TableName() string {
	return "ports"
}

type VMwareVM struct {
	VMID         string    `gorm:"column:vm_id;size:50;primaryKey"`
	AssetID      string    `gorm:"column:asset_id;not null"`
	VMName       string    `gorm:"column:vm_name;size:255;not null"`
	Hypervisor   string    `gorm:"column:hypervisor;size:100;not null"`
	CPUCount     int32     `gorm:"column:cpu_count;not null"`
	MemoryMB     int32     `gorm:"column:memory_mb;not null"`
	DiskSizeGB   int       `gorm:"column:disk_size_gb;not null"`
	PowerState   string    `gorm:"column:power_state;type:enum('On','Off','Suspended');not null"`
	LastSyncedAt time.Time `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Assets `gorm:"foreignKey:AssetID"`
}

func (VMwareVM) TableName() string {
	return "vmware_vms"
}

// Add unique constraints
type UniqueConstraints struct{}

func (u UniqueConstraints) ApplyConstraints(db *gorm.DB) error {
	// Add unique constraint for asset name and hostname combination
	if err := db.Exec("ALTER TABLE assets ADD CONSTRAINT assets_name_hostname_unique UNIQUE (name, hostname)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	// Add unique constraint for interface and IP combination (using new table name)
	if err := db.Exec("ALTER TABLE ips ADD CONSTRAINT ips_interface_id_ip_address_unique UNIQUE (interface_id, ip_address)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	// Add unique constraint for zone, interface, and VLAN combination (matching new schema)
	if err := db.Exec("ALTER TABLE zone_details ADD CONSTRAINT zone_details_zone_id_firewall_interface_id_vlan_table_id_unique UNIQUE (zone_id, firewall_interface_id, vlan_table_id)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	return nil
}
