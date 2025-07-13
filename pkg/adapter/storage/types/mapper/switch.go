package mapper

import (
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// SwitchMetadataDomain represents switch details in domain layer
type SwitchMetadataDomain struct {
	ID        string
	AssetID   string
	Username  string
	Password  string
	Port      int
	Brand     string
	CreatedAt interface{}
	UpdatedAt interface{}
}

// SwitchVRFDomain represents switch VRF in domain layer
type SwitchVRFDomain struct {
	ID                 string
	SwitchID           string
	Name               string
	RouteDistinguisher *string
	Description        *string
	CreatedAt          interface{}
}

// SwitchVRFDetailsDomain represents switch VRF details in domain layer
type SwitchVRFDetailsDomain struct {
	ID          string
	SwitchVRFID string
	InterfaceID string
	VLANID      string
	CreatedAt   interface{}
}

// SwitchAccessRuleDomain represents switch access rule in domain layer
type SwitchAccessRuleDomain struct {
	ID          string
	SwitchID    string
	RuleNumber  *int
	Action      *string
	Protocol    *string
	Source      *string
	Destination *string
	Port        *string
	CreatedAt   interface{}
}

// SwitchInterfaceDomain represents switch interface in domain layer
type SwitchInterfaceDomain struct {
	ID            string
	SwitchID      string
	InterfaceID   string
	InterfaceName string
	InterfaceType string
	Status        string
	Speed         *string
	Duplex        *string
	MTU           *int
	Description   *string
	VLANID        *int
	TrunkVLANs    *string
	AccessVLAN    *int
	PortMode      *string
	CreatedAt     interface{}
	UpdatedAt     interface{}
}

// SwitchVLANDomain represents switch VLAN in domain layer
type SwitchVLANDomain struct {
	ID          string
	SwitchID    string
	VLANID      int
	VLANName    string
	Status      string
	Type        string
	Description *string
	CreatedAt   interface{}
	UpdatedAt   interface{}
}

// SwitchRouteDomain represents switch route in domain layer
type SwitchRouteDomain struct {
	ID            string
	SwitchID      string
	VRFName       *string
	Network       string
	Mask          string
	NextHop       *string
	Interface     *string
	Metric        *int
	AdminDistance *int
	Protocol      string
	Age           *string
	Tag           *string
	CreatedAt     interface{}
	UpdatedAt     interface{}
}

// SwitchNeighborDomain represents switch neighbor in domain layer
type SwitchNeighborDomain struct {
	ID           string
	SwitchID     string
	DeviceID     string
	LocalPort    string
	RemotePort   *string
	Platform     *string
	IPAddress    *string
	Capabilities *string
	Software     *string
	Duplex       *string
	Protocol     string
	CreatedAt    interface{}
	UpdatedAt    interface{}
}

// SwitchMetadataDomain2Storage converts domain to storage model
func SwitchMetadataDomain2Storage(domain SwitchMetadataDomain) *types.SwitchMetadata {
	return &types.SwitchMetadata{
		ID:       domain.ID,
		AssetID:  domain.AssetID,
		Username: domain.Username,
		Password: domain.Password,
		Port:     domain.Port,
		Brand:    domain.Brand,
	}
}
