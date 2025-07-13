package scanner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/cisco"
	"gorm.io/gorm"
)

// DataProcessor handles database operations and result processing
type DataProcessor interface {
	ProcessResults(ctx context.Context, result *scannerDomain.CiscoScanResult, scannerID int64) error
}

// SwitchRunner orchestrates the switch device scanning process
type SwitchRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
	processor     DataProcessor
	db            *gorm.DB
}

// NewSwitchRunner creates a new switch runner with dependencies
func NewSwitchRunner(assetRepo assetPort.Repo, db *gorm.DB) *SwitchRunner {
	switchRepo := storage.NewSwitchRepo(db)

	return &SwitchRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
		processor:     NewSwitchDataProcessor(assetRepo, switchRepo, db),
		db:            db,
	}
}

// Execute implements the scheduler.Scanner interface
func (r *SwitchRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteSwitchScan(ctx, scanner, scanJobID)
}

// ExecuteSwitchScan runs a switch device scan based on scanner configuration
func (r *SwitchRunner) ExecuteSwitchScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	log.Printf("Starting switch scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)

	// Create cancellable context and register scan
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	startTime := time.Now()

	// Get the existing asset ID for this scanner
	assetID, err := r.getAssetIDForScanner(ctx, scanner.ID)
	if err != nil {
		log.Printf("Error getting asset ID for scanner: %v", err)
		return err
	}

	// Execute the scan
	result, err := r.performScan(scanCtx, scanner, scanJobID)
	if err != nil {
		if scanCtx.Err() == context.Canceled {
			log.Printf("Switch scan was cancelled for job ID: %d", scanJobID)
			return context.Canceled
		}
		log.Printf("Error executing switch scan: %v", err)
		return err
	}

	result.ScanDuration = time.Since(startTime)
	result.ScanJobID = scanJobID
	result.AssetID = assetID.String()

	// Process and store results using existing asset
	return r.processor.ProcessResults(ctx, result, scanner.ID)
}

// getAssetIDForScanner retrieves the asset ID associated with the scanner
func (r *SwitchRunner) getAssetIDForScanner(ctx context.Context, scannerID int64) (uuid.UUID, error) {
	var switchMetadata types.SwitchMetadata
	if err := r.db.WithContext(ctx).Table("switch_metadata").
		Where("scanner_id = ?", scannerID).
		First(&switchMetadata).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to get scanner metadata: %w", err)
	}

	assetID, err := uuid.Parse(switchMetadata.AssetID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid asset ID format: %w", err)
	}

	return assetID, nil
}

// performScan executes the actual device scan using the Cisco client
func (r *SwitchRunner) performScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) (*scannerDomain.CiscoScanResult, error) {
	log.Printf("Performing switch scan on device: %s:%s using SSH", scanner.IP, r.getDefaultPort(scanner))

	if strings.ToUpper(scanner.Protocol) != "SSH" {
		return nil, fmt.Errorf("unsupported protocol: %s (only SSH is supported)", scanner.Protocol)
	}

	// Create Cisco client configuration
	config := cisco.ConnectConfig{
		Host:     scanner.IP,
		Port:     r.getDefaultPort(scanner),
		Username: scanner.Username,
		Password: scanner.Password,
		Timeout:  30 * time.Second,
	}

	// Create and connect the client
	client := cisco.NewClientInsecure(config)
	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	// Execute commands and get output
	commands := client.GetDefaultCommands()
	output, err := client.ExecuteCommands(ctx, commands)
	if err != nil {
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	// Parse output using the client
	ciscoResult, err := client.ParseOutput(output)
	if err != nil {
		return nil, fmt.Errorf("output parsing failed: %w", err)
	}

	// Convert cisco.CiscoScanResult to scannerDomain.CiscoScanResult
	result := &scannerDomain.CiscoScanResult{
		DeviceIP:         ciscoResult.DeviceIP,
		ConnectionMethod: ciscoResult.ConnectionMethod,
		ScanJobID:        scanJobID,
		SystemInfo:       r.convertSystemInfo(ciscoResult.SystemInfo),
		Interfaces:       r.convertInterfaces(ciscoResult.Interfaces),
		VLANs:            r.convertVLANs(ciscoResult.VLANs),
		VLANPorts:        r.convertVLANPorts(ciscoResult.VLANPorts),
		Neighbors:        r.convertNeighbors(ciscoResult.Neighbors),
		RoutingTable:     r.convertRoutingTable(ciscoResult.RoutingTable),
	}

	log.Printf("Switch SSH scan completed successfully for device: %s", scanner.IP)
	return result, nil
}

// getDefaultPort returns appropriate default port for SSH protocol
func (r *SwitchRunner) getDefaultPort(scanner scannerDomain.ScannerDomain) string {
	if scanner.Port != "" {
		return scanner.Port
	}
	return "22"
}

// Convert functions
func (r *SwitchRunner) convertSystemInfo(ciscoSysInfo cisco.CiscoSystemInfo) scannerDomain.CiscoSystemInfo {
	return scannerDomain.CiscoSystemInfo{
		Hostname:       ciscoSysInfo.Hostname,
		Model:          ciscoSysInfo.Model,
		SystemUptime:   ciscoSysInfo.SystemUptime,
		EthernetMAC:    ciscoSysInfo.EthernetMAC,
		ManagementIP:   ciscoSysInfo.ManagementIP,
		DomainName:     ciscoSysInfo.DomainName,
		Location:       ciscoSysInfo.Location,
		LastConfigTime: ciscoSysInfo.LastConfigTime,
	}
}

func (r *SwitchRunner) convertInterfaces(ciscoInterfaces []cisco.CiscoInterface) []scannerDomain.CiscoInterface {
	var interfaces []scannerDomain.CiscoInterface
	for _, ciscoIface := range ciscoInterfaces {
		iface := scannerDomain.CiscoInterface{
			Name:        ciscoIface.Name,
			Description: ciscoIface.Description,
			IPAddress:   ciscoIface.IPAddress,
			SubnetMask:  ciscoIface.SubnetMask,
			Status:      ciscoIface.Status,
			Protocol:    ciscoIface.Protocol,
			MacAddress:  ciscoIface.MacAddress,
			VLANs:       ciscoIface.VLANs,
		}
		if ciscoIface.AssetID != nil {
			iface.SetAssetID(*ciscoIface.AssetID)
		}
		interfaces = append(interfaces, iface)
	}
	return interfaces
}

func (r *SwitchRunner) convertVLANs(ciscoVLANs []cisco.CiscoVLAN) []scannerDomain.CiscoVLAN {
	var vlans []scannerDomain.CiscoVLAN
	for _, ciscoVlan := range ciscoVLANs {
		vlans = append(vlans, scannerDomain.CiscoVLAN{
			ID:     ciscoVlan.ID,
			Name:   ciscoVlan.Name,
			Status: ciscoVlan.Status,
			Ports:  ciscoVlan.Ports,
			Type:   ciscoVlan.Type,
			Parent: ciscoVlan.Parent,
		})
	}
	return vlans
}

func (r *SwitchRunner) convertVLANPorts(ciscoVLANPorts []cisco.CiscoVLANPort) []scannerDomain.CiscoVLANPort {
	var vlanPorts []scannerDomain.CiscoVLANPort
	for _, ciscoVlanPort := range ciscoVLANPorts {
		vlanPorts = append(vlanPorts, scannerDomain.CiscoVLANPort{
			ID:         ciscoVlanPort.ID,
			VlanID:     ciscoVlanPort.VlanID,
			VlanName:   ciscoVlanPort.VlanName,
			PortName:   ciscoVlanPort.PortName,
			PortType:   ciscoVlanPort.PortType,
			PortStatus: ciscoVlanPort.PortStatus,
		})
	}
	return vlanPorts
}

func (r *SwitchRunner) convertNeighbors(ciscoNeighbors []cisco.CiscoNeighbor) []scannerDomain.CiscoNeighbor {
	var neighbors []scannerDomain.CiscoNeighbor
	for _, ciscoNeighbor := range ciscoNeighbors {
		neighbors = append(neighbors, scannerDomain.CiscoNeighbor{
			DeviceID:     ciscoNeighbor.DeviceID,
			LocalPort:    ciscoNeighbor.LocalPort,
			RemotePort:   ciscoNeighbor.RemotePort,
			Platform:     ciscoNeighbor.Platform,
			IPAddress:    ciscoNeighbor.IPAddress,
			Capabilities: ciscoNeighbor.Capabilities,
			Software:     ciscoNeighbor.Software,
			Duplex:       ciscoNeighbor.Duplex,
			Protocol:     ciscoNeighbor.Protocol,
		})
	}
	return neighbors
}

func (r *SwitchRunner) convertRoutingTable(ciscoRoutes []cisco.CiscoRoutingEntry) []scannerDomain.CiscoRoutingEntry {
	var routes []scannerDomain.CiscoRoutingEntry
	for _, ciscoRoute := range ciscoRoutes {
		routes = append(routes, scannerDomain.CiscoRoutingEntry{
			Network:       ciscoRoute.Network,
			Mask:          ciscoRoute.Mask,
			NextHop:       ciscoRoute.NextHop,
			Interface:     ciscoRoute.Interface,
			Metric:        ciscoRoute.Metric,
			AdminDistance: ciscoRoute.AdminDistance,
			Protocol:      ciscoRoute.Protocol,
			Age:           ciscoRoute.Age,
			Tag:           ciscoRoute.Tag,
		})
	}
	return routes
}

// Cancel and status methods
func (r *SwitchRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

func (r *SwitchRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// SwitchDataProcessor processes and stores switch scan results using existing asset
type SwitchDataProcessor struct {
	assetRepo  assetPort.Repo
	switchRepo *storage.SwitchRepo
	db         *gorm.DB
}

// NewSwitchDataProcessor creates a new switch data processor
func NewSwitchDataProcessor(assetRepo assetPort.Repo, switchRepo *storage.SwitchRepo, db *gorm.DB) *SwitchDataProcessor {
	return &SwitchDataProcessor{
		assetRepo:  assetRepo,
		switchRepo: switchRepo,
		db:         db,
	}
}

// ProcessResults processes scan results and updates existing asset and switch data
func (p *SwitchDataProcessor) ProcessResults(ctx context.Context, result *scannerDomain.CiscoScanResult, scannerID int64) error {
	log.Printf("Processing switch scan results for device: %s using existing asset: %s", result.DeviceIP, result.AssetID)

	assetID, err := uuid.Parse(result.AssetID)
	if err != nil {
		return fmt.Errorf("invalid asset ID: %w", err)
	}

	// Update asset with scan results
	if err := p.updateAssetWithScanResults(ctx, assetID, result); err != nil {
		log.Printf("Error updating asset: %v", err)
		return err
	}

	// Link asset to scan job
	if err := p.assetRepo.LinkAssetToScanJob(ctx, assetID, result.ScanJobID); err != nil {
		log.Printf("Error linking asset to scan job: %v", err)
	}

	// Store/update switch-specific data using existing schema
	if err := p.storeSwitchData(ctx, result, assetID, scannerID); err != nil {
		log.Printf("Error storing switch data: %v", err)
		return err
	}

	log.Printf("Successfully processed switch device %s (Asset ID: %s)", result.DeviceIP, result.AssetID)
	return nil
}

// storeSwitchData stores all switch-related data using existing tables
func (p *SwitchDataProcessor) storeSwitchData(ctx context.Context, result *scannerDomain.CiscoScanResult, assetID uuid.UUID, scannerID int64) error {
	// Delete existing data first to avoid duplicates
	if err := p.deleteExistingSwitchData(ctx, assetID); err != nil {
		log.Printf("Error deleting existing switch data: %v", err)
		return err
	}

	// Store interfaces using existing interfaces table
	if err := p.storeInterfaces(ctx, result.Interfaces, assetID); err != nil {
		return fmt.Errorf("failed to store interfaces: %w", err)
	}

	// Store VLANs using existing vlans table
	if err := p.storeVLANs(ctx, result.VLANs, assetID); err != nil {
		return fmt.Errorf("failed to store VLANs: %w", err)
	}

	// Store neighbors in switch_neighbors table
	if err := p.storeSwitchNeighbors(ctx, result.Neighbors, assetID); err != nil {
		return fmt.Errorf("failed to store neighbors: %w", err)
	}

	log.Printf("Successfully stored %d interfaces, %d VLANs, and %d neighbors for asset %s",
		len(result.Interfaces), len(result.VLANs), len(result.Neighbors), assetID.String())

	return nil
}

// deleteExistingSwitchData removes existing switch-related data for an asset
func (p *SwitchDataProcessor) deleteExistingSwitchData(ctx context.Context, assetID uuid.UUID) error {
	return p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		assetIDStr := assetID.String()

		// Soft delete existing interfaces for this asset
		if err := tx.Table("interfaces").
			Where("asset_id = ?", assetIDStr).
			Update("deleted_at", time.Now()).Error; err != nil {
			return err
		}

		// Soft delete existing VLANs for this asset
		if err := tx.Table("vlans").
			Where("asset_id = ?", assetIDStr).
			Update("deleted_at", time.Now()).Error; err != nil {
			return err
		}

		// Hard delete existing neighbors for this asset
		if err := tx.Table("switch_neighbors").
			Where("switch_id = ?", assetIDStr).
			Delete(&types.SwitchNeighbor{}).Error; err != nil {
			log.Printf("Warning: Error deleting switch neighbors (table may not exist): %v", err)
		}

		// Hard delete existing IPs for this asset - we'll re-add them including management IP
		if err := tx.Table("ips").
			Where("asset_id = ?", assetIDStr).
			Delete(&types.IPs{}).Error; err != nil {
			return err
		}

		return nil
	})
}

// storeInterfaces stores switch interface data using existing interfaces table
func (p *SwitchDataProcessor) storeInterfaces(ctx context.Context, interfaces []scannerDomain.CiscoInterface, assetID uuid.UUID) error {
	if len(interfaces) == 0 {
		return nil
	}

	// Initialize default interface types if they don't exist
	if err := p.initializeDefaultInterfaceTypes(ctx); err != nil {
		return fmt.Errorf("failed to initialize interface types: %w", err)
	}

	for _, iface := range interfaces {
		// Determine interface type
		interfaceTypeName := p.determineInterfaceType(iface.Name)
		interfaceTypeID, err := p.getInterfaceTypeID(ctx, interfaceTypeName)
		if err != nil {
			log.Printf("Error getting interface type ID for %s: %v", interfaceTypeName, err)
			interfaceTypeID = 1 // fallback to first type
		}

		// Create interface record using existing interfaces table
		interfaceRecord := types.Interfaces{
			ID:                   uuid.New().String(),
			InterfaceName:        iface.Name,
			InterfaceTypeID:      interfaceTypeID,
			AssetID:              stringPtr(assetID.String()),
			Description:          iface.Description,
			OperationalStatus:    normalizeStatus(iface.Status),
			AdminStatus:          normalizeAdminStatus(iface.Protocol),
			MacAddress:           iface.MacAddress,
			VendorSpecificConfig: "{}", // Empty JSON to satisfy constraint
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		// Set VLAN information if available
		if len(iface.VLANs) > 0 {
			if vlanID := p.parseVLANID(iface.VLANs[0]); vlanID > 0 {
				interfaceRecord.VLANId = &vlanID
			}
		}

		if err := p.db.WithContext(ctx).Table("interfaces").Create(&interfaceRecord).Error; err != nil {
			log.Printf("Error creating interface %s: %v", iface.Name, err)
			continue
		}

		// Add interface IP to ips table if it has an IP address
		if iface.IPAddress != "" {
			// Check if this IP already exists (avoid duplicates with management IP)
			var count int64
			p.db.WithContext(ctx).Table("ips").
				Where("asset_id = ? AND ip = ?", assetID.String(), iface.IPAddress).
				Count(&count)

			if count == 0 {
				// Create new IP record for this interface
				interfaceIP := types.IPs{
					ID:          uuid.New().String(),
					AssetID:     assetID.String(),
					InterfaceID: &interfaceRecord.ID, // Link to the interface
					IPAddress:   iface.IPAddress,
					MacAddress:  iface.MacAddress,
					CreatedAt:   time.Now(),
				}

				if err := p.db.WithContext(ctx).Table("ips").Create(&interfaceIP).Error; err != nil {
					log.Printf("Error creating interface IP %s: %v", iface.IPAddress, err)
				}
			}
		}
	}

	return nil
}

// storeVLANs stores switch VLAN data using existing vlans table
func (p *SwitchDataProcessor) storeVLANs(ctx context.Context, vlans []scannerDomain.CiscoVLAN, assetID uuid.UUID) error {
	if len(vlans) == 0 {
		return nil
	}

	for _, vlan := range vlans {
		// Create VLAN record using existing vlans table
		vlanRecord := types.VLANs{
			ID:                   uuid.New().String(),
			VLANNumber:           vlan.ID,
			VLANName:             vlan.Name,
			Description:          vlan.Status,  // Store status in description for now
			IsNative:             vlan.ID == 1, // VLAN 1 is typically native
			DeviceType:           "switch",
			AssetID:              assetID.String(),
			VendorSpecificConfig: "{}", // Empty JSON to satisfy constraint
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		if err := p.db.WithContext(ctx).Table("vlans").Create(&vlanRecord).Error; err != nil {
			log.Printf("Error creating VLAN %d: %v", vlan.ID, err)
			continue
		}
	}

	return nil
}

// storeSwitchNeighbors stores switch neighbor data in switch_neighbors table
func (p *SwitchDataProcessor) storeSwitchNeighbors(ctx context.Context, neighbors []scannerDomain.CiscoNeighbor, assetID uuid.UUID) error {
	if len(neighbors) == 0 {
		return nil
	}

	for _, neighbor := range neighbors {
		// Create neighbor record
		neighborRecord := types.SwitchNeighbor{
			ID:           uuid.New().String(),
			SwitchID:     assetID.String(),
			DeviceID:     neighbor.DeviceID,
			LocalPort:    neighbor.LocalPort,
			RemotePort:   stringPtrOrNil(neighbor.RemotePort),
			Platform:     stringPtrOrNil(neighbor.Platform),
			IPAddress:    stringPtrOrNil(neighbor.IPAddress),
			Capabilities: stringPtrOrNil(neighbor.Capabilities),
			Software:     stringPtrOrNil(neighbor.Software),
			Duplex:       stringPtrOrNil(neighbor.Duplex),
			Protocol:     neighbor.Protocol,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := p.db.WithContext(ctx).Table("switch_neighbors").Create(&neighborRecord).Error; err != nil {
			log.Printf("Error creating switch neighbor %s (table may not exist): %v", neighbor.DeviceID, err)
			continue
		}
	}

	log.Printf("Successfully stored %d neighbors for asset %s", len(neighbors), assetID.String())
	return nil
}

// updateAssetWithScanResults updates the existing asset with information from the scan
func (p *SwitchDataProcessor) updateAssetWithScanResults(ctx context.Context, assetID uuid.UUID, result *scannerDomain.CiscoScanResult) error {
	updates := map[string]interface{}{
		"updated_at": time.Now(),
	}

	// Update hostname if we got it from the scan
	if result.SystemInfo.Hostname != "" {
		updates["hostname"] = result.SystemInfo.Hostname
		updates["name"] = result.SystemInfo.Hostname // Also update name
	}

	// Update OS information
	if result.SystemInfo.Model != "" {
		updates["os_name"] = fmt.Sprintf("Cisco %s", result.SystemInfo.Model)
	}

	// Update description with more details
	updates["description"] = fmt.Sprintf("Cisco %s switch - %s (Last scanned: %s)",
		result.SystemInfo.Model,
		result.SystemInfo.SystemUptime,
		time.Now().Format("2006-01-02 15:04:05"))

	// Update the asset
	if err := p.db.WithContext(ctx).Table("assets").
		Where("id = ?", assetID.String()).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update asset: %w", err)
	}

	// Update asset IPs with MAC addresses from interfaces
	if err := p.updateAssetIPs(ctx, assetID, result); err != nil {
		log.Printf("Error updating asset IPs: %v", err)
	}

	return nil
}

// updateAssetIPs updates IP addresses and MAC addresses for the asset
func (p *SwitchDataProcessor) updateAssetIPs(ctx context.Context, assetID uuid.UUID, result *scannerDomain.CiscoScanResult) error {
	// Add management IP to ips table
	managementIP := types.IPs{
		ID:         uuid.New().String(),
		AssetID:    assetID.String(),
		IPAddress:  result.DeviceIP,
		MacAddress: result.SystemInfo.EthernetMAC,
		CreatedAt:  time.Now(),
	}

	if err := p.db.WithContext(ctx).Table("ips").Create(&managementIP).Error; err != nil {
		log.Printf("Error creating management IP %s: %v", result.DeviceIP, err)
	}

	return nil
}

// Helper functions
func (p *SwitchDataProcessor) initializeDefaultInterfaceTypes(ctx context.Context) error {
	defaultTypes := []types.InterfaceTypes{
		{TypeName: "physical", Description: "Physical network interface"},
		{TypeName: "vlan", Description: "VLAN interface"},
		{TypeName: "loopback", Description: "Loopback interface"},
		{TypeName: "tunnel", Description: "Tunnel interface"},
		{TypeName: "port-channel", Description: "Port channel interface"},
	}

	for _, interfaceType := range defaultTypes {
		var existingType types.InterfaceTypes
		err := p.db.WithContext(ctx).Where("type_name = ?", interfaceType.TypeName).First(&existingType).Error

		if err == gorm.ErrRecordNotFound {
			// Interface type doesn't exist, create it
			if err := p.db.WithContext(ctx).Create(&interfaceType).Error; err != nil {
				log.Printf("Error creating interface type %s: %v", interfaceType.TypeName, err)
				return err
			}
			log.Printf("Created interface type: %s", interfaceType.TypeName)
		} else if err != nil {
			log.Printf("Error checking interface type %s: %v", interfaceType.TypeName, err)
			return err
		}
	}

	return nil
}

// getInterfaceTypeID gets the interface type ID for a given type name
func (p *SwitchDataProcessor) getInterfaceTypeID(ctx context.Context, typeName string) (uint, error) {
	var interfaceType types.InterfaceTypes
	err := p.db.WithContext(ctx).Where("type_name = ?", typeName).First(&interfaceType).Error
	if err != nil {
		return 0, err
	}
	return interfaceType.ID, nil
}

// determineInterfaceType determines the interface type based on interface name
func (p *SwitchDataProcessor) determineInterfaceType(interfaceName string) string {
	name := strings.ToLower(interfaceName)
	switch {
	case strings.Contains(name, "vlan"):
		return "vlan"
	case strings.Contains(name, "loopback"):
		return "loopback"
	case strings.Contains(name, "tunnel"):
		return "tunnel"
	case strings.Contains(name, "port-channel"):
		return "port-channel"
	default:
		return "physical"
	}
}

func (p *SwitchDataProcessor) parseVLANID(vlanStr string) int {
	if vlanStr == "" {
		return 0
	}

	// Try to extract numeric part
	var vlanID int
	if _, err := fmt.Sscanf(strings.TrimSpace(vlanStr), "%d", &vlanID); err == nil {
		return vlanID
	}

	return 0
}

// Helper functions
func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func normalizeStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "up", "active", "enabled":
		return "up"
	case "down", "inactive", "disabled", "administratively down":
		return "down"
	default:
		return "unknown"
	}
}

func normalizeAdminStatus(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch protocol {
	case "up", "active", "enabled":
		return "up"
	default:
		return "down"
	}
}
