package mapper

import (
	"github.com/google/uuid"
	Domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	ScannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gorm.io/gorm"
)

// VendorService handles vendor operations
type VendorService struct {
	db *gorm.DB
}

// NewVendorService creates a new vendor service
func NewVendorService(db *gorm.DB) *VendorService {
	return &VendorService{db: db}
}

// GetOrCreateVendor gets or creates a vendor by name
func (v *VendorService) GetOrCreateVendor(vendorName string) (uint, error) {
	var vendor types.Vendors

	// Try to find existing vendor
	err := v.db.Where("vendor_name = ?", vendorName).First(&vendor).Error
	if err == nil {
		return vendor.ID, nil
	}

	if err != gorm.ErrRecordNotFound {
		return 0, err
	}

	// Create new vendor if not found
	vendor = types.Vendors{
		VendorName: vendorName,
		VendorCode: generateVendorCode(vendorName),
	}

	if err := v.db.Create(&vendor).Error; err != nil {
		return 0, err
	}

	return vendor.ID, nil
}

// generateVendorCode generates a vendor code from vendor name
func generateVendorCode(vendorName string) string {
	if len(vendorName) >= 3 {
		return vendorName[:3]
	}
	return vendorName
}

// AssetDomain2StorageWithVendor converts domain asset to storage with proper vendor handling
func AssetDomain2StorageWithVendor(asset Domain.AssetDomain, db *gorm.DB, scannerType string) (*types.Assets, []*types.IPs, error) {
	vendorService := NewVendorService(db)

	// Determine vendor name based on scanner type or asset type
	vendorName := "Unknown"
	switch scannerType {
	case "SWITCH":
		vendorName = "Cisco" // Default for switches
	case "FIREWALL":
		vendorName = "Fortinet" // Default for firewalls
	case "NMAP":
		vendorName = "Generic" // For network scans
	case "VMWARE":
		vendorName = "VMware"
	case "NESSUS":
		vendorName = "Generic"
	default:
		if asset.OSName != "" {
			// Try to extract vendor from OS name
			if contains(asset.OSName, "Cisco") {
				vendorName = "Cisco"
			} else if contains(asset.OSName, "Fortinet") {
				vendorName = "Fortinet"
			} else if contains(asset.OSName, "VMware") {
				vendorName = "VMware"
			} else if contains(asset.OSName, "Windows") {
				vendorName = "Microsoft"
			} else if contains(asset.OSName, "Linux") {
				vendorName = "Linux"
			}
		}
	}

	// Get or create vendor
	vendorID, err := vendorService.GetOrCreateVendor(vendorName)
	if err != nil {
		return nil, nil, err
	}

	// Convert risk int to string enum
	riskStr := "medium" // default
	switch asset.Risk {
	case 1:
		riskStr = "low"
	case 2:
		riskStr = "medium"
	case 3:
		riskStr = "high"
	case 4:
		riskStr = "critical"
	}

	// Convert asset value from int to float64
	assetValue := float64(asset.AssetValue)

	assetStorage := &types.Assets{
		ID:               asset.ID.String(),
		VendorID:         vendorID, // Use the proper vendor ID
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           asset.OSName,
		OSVersion:        asset.OSVersion,
		Description:      asset.Description,
		AssetType:        asset.Type,
		Risk:             riskStr,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       assetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        asset.UpdatedAt,
	}

	// Set discovered_by if available
	if asset.DiscoveredBy != "" {
		assetStorage.DiscoveredBy = &asset.DiscoveredBy
	}

	// Create AssetIP objects for each IP
	assetIPs := make([]*types.IPs, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		mac := ip.MACAddress
		if mac == "" {
			mac = "" // Leave empty if not provided
		}

		assetIPID := ip.ID
		if assetIPID == "" {
			assetIPID = uuid.New().String()
		}

		assetIP := &types.IPs{
			ID:         assetIPID,
			AssetID:    asset.ID.String(),
			IPAddress:  ip.IP,
			MacAddress: mac,
			CreatedAt:  asset.CreatedAt,
		}

		if ip.InterfaceID != "" {
			assetIP.InterfaceID = &ip.InterfaceID
		}

		if ip.CIDRPrefix != nil {
			assetIP.CIDRPrefix = ip.CIDRPrefix
		}

		assetIPs = append(assetIPs, assetIP)
	}

	return assetStorage, assetIPs, nil
}

// Helper function to check if string contains substring (case insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			indexOf(s, substr) != -1)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Keep the original function for backward compatibility
func AssetDomain2Storage(asset Domain.AssetDomain) (*types.Assets, []*types.IPs) {
	// Convert risk int to string enum
	riskStr := "medium" // default
	switch asset.Risk {
	case 1:
		riskStr = "low"
	case 2:
		riskStr = "medium"
	case 3:
		riskStr = "high"
	case 4:
		riskStr = "critical"
	}

	// Convert asset value from int to float64
	assetValue := float64(asset.AssetValue)

	assetStorage := &types.Assets{
		ID:               asset.ID.String(),
		VendorID:         1, // Default - this should be updated to use the new method
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           asset.OSName,
		OSVersion:        asset.OSVersion,
		Description:      asset.Description,
		AssetType:        asset.Type,
		Risk:             riskStr,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       assetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        asset.UpdatedAt,
	}

	// Create AssetIP objects for each IP
	assetIPs := make([]*types.IPs, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		mac := ip.MACAddress
		if mac == "" {
			mac = "" // Leave empty if not provided
		}

		assetIPID := ip.ID
		if assetIPID == "" {
			assetIPID = uuid.New().String()
		}

		assetIP := &types.IPs{
			ID:         assetIPID,
			AssetID:    asset.ID.String(),
			IPAddress:  ip.IP,
			MacAddress: mac,
			CreatedAt:  asset.CreatedAt,
		}

		if ip.InterfaceID != "" {
			assetIP.InterfaceID = &ip.InterfaceID
		}

		if ip.CIDRPrefix != nil {
			assetIP.CIDRPrefix = ip.CIDRPrefix
		}

		assetIPs = append(assetIPs, assetIP)
	}

	return assetStorage, assetIPs
}

func AssetStorage2Domain(asset types.Assets) (*Domain.AssetDomain, error) {
	uid, err := Domain.AssetUUIDFromString(asset.ID)
	if err != nil {
		return nil, err
	}

	ports := make([]Domain.Port, 0, len(asset.Ports))
	for _, port := range asset.Ports {
		var serviceName, serviceVersion, description string
		if port.ServiceName != nil {
			serviceName = *port.ServiceName
		}
		if port.ServiceVersion != nil {
			serviceVersion = *port.ServiceVersion
		}
		if port.Description != nil {
			description = *port.Description
		}

		ports = append(ports, Domain.Port{
			ID:             port.ID,
			AssetID:        port.AssetID,
			PortNumber:     port.PortNumber,
			Protocol:       port.Protocol,
			State:          port.State,
			ServiceName:    serviceName,
			ServiceVersion: serviceVersion,
			Description:    description,
			DiscoveredAt:   port.DiscoveredAt,
		})
	}

	vms := make([]Domain.VMwareVM, 0, len(asset.VMwareVMs))
	for _, vm := range asset.VMwareVMs {
		vms = append(vms, Domain.VMwareVM{
			VMID:         vm.VMID,
			AssetID:      vm.AssetID,
			VMName:       vm.VMName,
			Hypervisor:   vm.Hypervisor,
			CPUCount:     int32(vm.CPUCount),
			MemoryMB:     int32(vm.MemoryMB),
			DiskSizeGB:   vm.DiskSizeGB,
			PowerState:   vm.PowerState,
			LastSyncedAt: vm.LastSyncedAt,
		})
	}

	ips := make([]Domain.AssetIP, 0, len(asset.IPs))
	for _, ip := range asset.IPs {
		interfaceID := ""
		if ip.InterfaceID != nil {
			interfaceID = *ip.InterfaceID
		}

		ips = append(ips, Domain.AssetIP{
			ID:          ip.ID,
			AssetID:     ip.AssetID,
			InterfaceID: interfaceID,
			IP:          ip.IPAddress,
			MACAddress:  ip.MacAddress,
			CIDRPrefix:  ip.CIDRPrefix,
		})
	}

	// Convert risk string enum back to int
	risk := 2 // default medium
	switch asset.Risk {
	case "low":
		risk = 1
	case "medium":
		risk = 2
	case "high":
		risk = 3
	case "critical":
		risk = 4
	}

	// Convert asset value from float64 to int
	assetValue := int(asset.AssetValue)

	// Handle deleted_at for domain model
	updatedAt := asset.UpdatedAt
	if asset.DeletedAt != nil {
		// If deleted, use deletion time as updated time
		updatedAt = *asset.DeletedAt
	}

	// Get discovered_by value
	discoveredBy := ""
	if asset.DiscoveredBy != nil {
		discoveredBy = *asset.DiscoveredBy
	}

	return &Domain.AssetDomain{
		ID:               uid,
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           asset.OSName,
		OSVersion:        asset.OSVersion,
		Type:             asset.AssetType,
		Description:      asset.Description,
		Risk:             risk,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       assetValue,
		DiscoveredBy:     discoveredBy,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        updatedAt,
		Ports:            ports,
		VMwareVMs:        vms,
		AssetIPs:         ips,
	}, nil
}

func AssetStorage2DomainWithScannerType(asset types.Assets, scannerType string) (*Domain.AssetDomain, error) {
	assetDomain, err := AssetStorage2Domain(asset)
	if err != nil {
		return nil, err
	}

	scannerObj := &ScannerDomain.ScannerDomain{
		Type: scannerType,
	}

	assetDomain.Scanner = scannerObj
	return assetDomain, nil
}

// PortDomain2Storage maps domain.Port to storage.Port
func PortDomain2Storage(port Domain.Port) *types.Port {
	portStorage := &types.Port{
		ID:           port.ID,
		AssetID:      port.AssetID,
		PortNumber:   port.PortNumber,
		Protocol:     port.Protocol,
		State:        port.State,
		DiscoveredAt: port.DiscoveredAt,
	}

	// Only set pointer fields if they have values
	if port.ServiceName != "" {
		portStorage.ServiceName = &port.ServiceName
	}
	if port.ServiceVersion != "" {
		portStorage.ServiceVersion = &port.ServiceVersion
	}
	if port.Description != "" {
		portStorage.Description = &port.Description
	}

	return portStorage
}

// AssetIPDomain2Storage maps domain.AssetIP to storage.IPs
func AssetIPDomain2Storage(ip Domain.AssetIP) *types.IPs {
	ipID := ip.ID
	if ipID == "" {
		ipID = uuid.New().String()
	}

	ipStorage := &types.IPs{
		ID:         ipID,
		AssetID:    ip.AssetID,
		IPAddress:  ip.IP,
		MacAddress: ip.MACAddress,
	}

	if ip.InterfaceID != "" {
		ipStorage.InterfaceID = &ip.InterfaceID
	}

	if ip.CIDRPrefix != nil {
		ipStorage.CIDRPrefix = ip.CIDRPrefix
	}

	return ipStorage
}
