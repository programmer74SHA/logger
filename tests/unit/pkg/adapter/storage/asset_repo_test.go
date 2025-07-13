package storage_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormMysql "gorm.io/driver/mysql"
	"gorm.io/gorm"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	domainFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/domain"
)

type AssetRepoTestSuite struct {
	db     *sql.DB
	gormDB *gorm.DB
	mock   sqlmock.Sqlmock
	repo   assetPort.Repo
	ctx    context.Context
	now    time.Time
}

func setupAssetRepoTest(t *testing.T) *AssetRepoTestSuite {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	gormDB, err := gorm.Open(gormMysql.New(gormMysql.Config{
		Conn:                      db,
		SkipInitializeWithVersion: true,
	}), &gorm.Config{})
	require.NoError(t, err)

	repo := storage.NewAssetRepo(gormDB)
	ctx := context.Background()
	now := time.Now()

	return &AssetRepoTestSuite{
		db:     db,
		gormDB: gormDB,
		mock:   mock,
		repo:   repo,
		ctx:    ctx,
		now:    now,
	}
}

func (suite *AssetRepoTestSuite) tearDown() {
	suite.db.Close()
}

func TestAssetRepository_Create_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock the hostname check query first (must return 0 for no duplicates)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock the asset INSERT - GORM fields in actual order
	// Convert domain risk (int) to storage risk (string) as per mapper
	expectedRisk := "low"
	expectedAssetValue := float64(assetDomain.AssetValue)

	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			sqlmock.AnyArg(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&assetDomain.OSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			assetDomain.Type,
			sqlmock.AnyArg(), // discovered_by field
			expectedRisk,
			&assetDomain.LoggingCompleted,
			expectedAssetValue,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_DuplicateHostname(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock the hostname check query to return 1 (duplicate exists)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrHostnameAlreadyExists, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_DatabaseConnectionError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock database connection error on hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnError(sql.ErrConnDone)

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_WithAssetIPs(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.100", "10.0.0.50"})

	// Mock hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock the IP existence check that happens when there are IPs
	suite.mock.ExpectQuery("SELECT \\* FROM `ips` WHERE ip_address IN \\(\\?\\,\\?\\)").
		WithArgs("192.168.1.100", "10.0.0.50").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Mock asset insert
	// Convert domain risk (int) to storage risk (string) as per mapper
	expectedRisk := "low" // domain risk 1 maps to "low"
	expectedAssetValue := float64(assetDomain.AssetValue)

	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			sqlmock.AnyArg(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&assetDomain.OSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			assetDomain.Type,
			sqlmock.AnyArg(), // discovered_by field
			expectedRisk,
			&assetDomain.LoggingCompleted,
			expectedAssetValue,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock asset IP inserts
	for range assetDomain.AssetIPs {
		suite.mock.ExpectExec("INSERT INTO `ips`").
			WithArgs(
				sqlmock.AnyArg(),
				assetDomain.ID.String(), // AssetID
				sqlmock.AnyArg(),        // IP
				sqlmock.AnyArg(),        // MACAddress
				sqlmock.AnyArg(),
				sqlmock.AnyArg(),
				sqlmock.AnyArg(), // CreatedAt
				sqlmock.AnyArg(), // UpdatedAt
				sqlmock.AnyArg(), // DeletedAt
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_WithPorts(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomainWithPorts(3)

	// Mock hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock asset insert
	// Convert domain risk (int) to storage risk (string) as per mapper
	expectedRisk := "low" // domain risk 1 maps to "low"
	expectedAssetValue := float64(assetDomain.AssetValue)

	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			sqlmock.AnyArg(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&assetDomain.OSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			assetDomain.Type,
			sqlmock.AnyArg(), // discovered_by field
			expectedRisk,
			&assetDomain.LoggingCompleted,
			expectedAssetValue,
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
			sqlmock.AnyArg(), // deleted_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock port inserts - based on actual Port structure in types
	for range assetDomain.Ports {
		suite.mock.ExpectExec("INSERT INTO `ports`").
			WithArgs(
				sqlmock.AnyArg(),        // ID
				assetDomain.ID.String(), // AssetID
				sqlmock.AnyArg(),        // PortNumber
				sqlmock.AnyArg(),        // Protocol
				sqlmock.AnyArg(),        // State
				sqlmock.AnyArg(),        // ServiceName (pointer)
				sqlmock.AnyArg(),        // ServiceVersion (pointer)
				sqlmock.AnyArg(),        // Description (pointer)
				sqlmock.AnyArg(),        // DeletedAt (pointer)
				sqlmock.AnyArg(),        // DiscoveredAt
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_InvalidAssetData(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()
	assetDomain.Hostname = "" // Invalid empty hostname

	// Mock hostname check (empty hostname won't match)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs("").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction and constraint violation
	suite.mock.ExpectBegin()
	suite.mock.ExpectExec("INSERT INTO `assets`").
		WillReturnError(&mysql.MySQLError{Number: 1048, Message: "Column 'hostname' cannot be null"})
	suite.mock.ExpectRollback()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be null")
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_ContextCancellation(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock context cancellation error during the hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnError(context.Canceled)

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for GetByIDs method
func TestAssetRepository_GetByIDs_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID1 := uuid.New()
	assetUUIDs := []domain.AssetUUID{assetID1}

	// Mock the main query with a simplified expected result
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at", "deleted_at",
	}).
		AddRow(assetID1.String(), "Test Asset 1", "test.local", "host1",
			"Ubuntu", "20.04", "Test description 1", "Server", 1, false,
			100, suite.now, suite.now, nil)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetID1.String()).
		WillReturnRows(assetRows)

	// Mock the AssetIPs preload query
	ipsRows := sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "scan_type", "created_at", "updated_at", "deleted_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs(assetID1.String()).
		WillReturnRows(ipsRows)

	// Mock the Ports preload query
	portsRows := sqlmock.NewRows([]string{"id", "asset_id", "port_number", "service_name", "protocol", "state", "scan_type", "banner", "version", "created_at", "updated_at", "deleted_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `ports`").
		WithArgs(assetID1.String()).
		WillReturnRows(portsRows)

	// Mock the VMwareVMs preload query
	vmwareRows := sqlmock.NewRows([]string{"id", "asset_id", "vm_id", "vm_name", "created_at", "updated_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `vmware_vms`").
		WithArgs(assetID1.String()).
		WillReturnRows(vmwareRows)

	// Mock the scanner types query
	scannerRows := sqlmock.NewRows([]string{"asset_id", "scan_type"}).
		AddRow(assetID1.String(), "nmap")

	suite.mock.ExpectQuery("SELECT asj\\.asset_id, scanners\\.scan_type FROM asset_scan_jobs asj").
		WithArgs(assetID1.String()).
		WillReturnRows(scannerRows)

	// Act
	assets, err := suite.repo.GetByIDs(suite.ctx, assetUUIDs)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, "Test Asset 1", assets[0].Name)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetByIDs_EmptyList(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Act
	assets, err := suite.repo.GetByIDs(suite.ctx, []domain.AssetUUID{})

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 0)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetByIDs_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	assetUUIDs := []domain.AssetUUID{assetID}

	// Mock database error
	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetID.String()).
		WillReturnError(sql.ErrConnDone)

	// Act
	assets, err := suite.repo.GetByIDs(suite.ctx, assetUUIDs)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, assets)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for Get method
func TestAssetRepository_Get_WithFilters(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{
		Hostname: "test-host",
	}

	assetID := uuid.New()
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at", "deleted_at",
	}).AddRow(assetID.String(), "Test Asset", "test.local", "test-host",
		"Ubuntu", "20.04", "Test description", "Server", 1, false,
		100, suite.now, suite.now, nil)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs("%test-host%").
		WillReturnRows(assetRows)

	// Mock scanner types query
	suite.mock.ExpectQuery("SELECT asj").
		WillReturnRows(sqlmock.NewRows([]string{"asset_id", "scan_type"}))

	// Mock asset IPs query (called by getAssetIPs)
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Act
	assets, err := suite.repo.Get(suite.ctx, filters)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, "Test Asset", assets[0].Name)
	assert.Equal(t, "test-host", assets[0].Hostname)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Get_NoResults(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{
		Hostname: "nonexistent",
	}

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs("%nonexistent%").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "hostname", "os_name", "os_version", "description", "asset_type", "risk", "logging_completed", "asset_value", "created_at", "updated_at", "deleted_at"}))

	// Act
	assets, err := suite.repo.Get(suite.ctx, filters)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 0)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for Update method
func TestAssetRepository_Update_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()
	assetDomain.Name = "Updated Asset"
	assetDomain.Description = "Updated description"

	// Mock hostname uniqueness check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets` WHERE hostname = \\? AND id != \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.Hostname, assetDomain.ID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock current IPs query (happens inside transaction)
	suite.mock.ExpectQuery("SELECT \\* FROM `ips` WHERE asset_id = \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.ID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Mock asset update (simplified)
	suite.mock.ExpectExec("UPDATE `assets`").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock current ports query
	suite.mock.ExpectQuery("SELECT \\* FROM `ports` WHERE asset_id = \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.ID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "port", "protocol", "service", "created_at", "updated_at", "deleted_at"}))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.Update(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Update_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock hostname uniqueness check with error
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets` WHERE hostname = \\? AND id != \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.Hostname, assetDomain.ID.String()).
		WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.Update(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for UpdateAssetPorts method
func TestAssetRepository_UpdateAssetPorts_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	ports := []types.Port{
		{
			ID:         uuid.New().String(),
			AssetID:    assetID.String(),
			PortNumber: 80,
			Protocol:   "TCP",
			State:      "Up",
		},
	}

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock marking existing ports as deleted
	suite.mock.ExpectExec("UPDATE `ports`").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock creating new ports
	suite.mock.ExpectExec("INSERT INTO `ports`").
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.UpdateAssetPorts(suite.ctx, assetID, ports)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_UpdateAssetPorts_TransactionError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	ports := []types.Port{}

	// Mock transaction begin error
	suite.mock.ExpectBegin().WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.UpdateAssetPorts(suite.ctx, assetID, ports)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for LinkAssetToScanJob method
func TestAssetRepository_LinkAssetToScanJob_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	scanJobID := int64(123)

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock the asset-scanjob link insertion
	suite.mock.ExpectExec("INSERT INTO `asset_scan_jobs`").
		WithArgs(
			assetID.String(), // AssetID
			scanJobID,        // ScanJobID
			sqlmock.AnyArg(), // discovered_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.LinkAssetToScanJob(suite.ctx, assetID, scanJobID)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_LinkAssetToScanJob_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	scanJobID := int64(123)

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock database error
	suite.mock.ExpectExec("INSERT INTO `asset_scan_jobs`").
		WillReturnError(sql.ErrConnDone)

	suite.mock.ExpectRollback()

	// Act
	err := suite.repo.LinkAssetToScanJob(suite.ctx, assetID, scanJobID)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for StoreVMwareVM method
func TestAssetRepository_StoreVMwareVM_NewVM(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vmData := domain.VMwareVM{
		VMID:         "vm-123",
		AssetID:      uuid.New().String(),
		VMName:       "Test VM",
		Hypervisor:   "ESXi 7.0",
		CPUCount:     4,
		MemoryMB:     8192,
		DiskSizeGB:   100,
		PowerState:   "On",
		LastSyncedAt: time.Now(),
	}

	// Mock VM existence check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `vmware_vms`").
		WithArgs(vmData.VMID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock VM insertion
	suite.mock.ExpectExec("INSERT INTO `vmware_vms`").
		WithArgs(
			vmData.VMID,
			vmData.AssetID,
			vmData.VMName,
			vmData.Hypervisor,
			int(vmData.CPUCount),
			int(vmData.MemoryMB),
			vmData.DiskSizeGB,
			vmData.PowerState,
			sqlmock.AnyArg(), // LastSyncedAt
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.StoreVMwareVM(suite.ctx, vmData)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreVMwareVM_UpdateExisting(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vmData := domain.VMwareVM{
		VMID:         "vm-123",
		AssetID:      uuid.New().String(),
		VMName:       "Updated VM",
		Hypervisor:   "ESXi 7.0",
		CPUCount:     8,
		MemoryMB:     16384,
		DiskSizeGB:   200,
		PowerState:   "On",
		LastSyncedAt: time.Now(),
	}

	// Mock VM existence check (returns 1, meaning VM exists)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `vmware_vms`").
		WithArgs(vmData.VMID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock VM update
	suite.mock.ExpectExec("UPDATE `vmware_vms`").
		WithArgs(
			vmData.AssetID,       // asset_id
			int(vmData.CPUCount), // cpu_count
			vmData.DiskSizeGB,    // disk_size_gb
			vmData.Hypervisor,    // hypervisor
			sqlmock.AnyArg(),     // last_synced_at
			int(vmData.MemoryMB), // memory_mb
			vmData.PowerState,    // power_state
			vmData.VMName,        // vm_name
			vmData.VMID,          // WHERE vm_id condition
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.StoreVMwareVM(suite.ctx, vmData)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreVMwareVM_CheckExistenceError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vmData := domain.VMwareVM{
		VMID:    "vm-123",
		AssetID: uuid.New().String(),
		VMName:  "Test VM",
	}

	// Mock VM existence check with error
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `vmware_vms`").
		WithArgs(vmData.VMID).
		WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.StoreVMwareVM(suite.ctx, vmData)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for DeleteAssets method
func TestAssetRepository_DeleteAssets_SingleUUID(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	params := domain.NewDeleteParamsWithUUID(assetID)

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock the deletion update
	suite.mock.ExpectExec("UPDATE `assets`").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), assetID.String()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	affected, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 1, affected)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_DeleteAssets_MultipleUUIDs(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID1 := uuid.New()
	assetID2 := uuid.New()
	params := domain.NewDeleteParamsWithUUIDs([]domain.AssetUUID{assetID1, assetID2})

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock the deletion update
	suite.mock.ExpectExec("UPDATE `assets`").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), assetID1.String(), assetID2.String()).
		WillReturnResult(sqlmock.NewResult(2, 2))

	suite.mock.ExpectCommit()

	// Act
	affected, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 2, affected)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_DeleteAssets_WithFilters(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{
		OSName: "Ubuntu",
		Type:   "Server",
	}
	params := domain.NewDeleteParamsWithFilters(filters)

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock the deletion update with filters
	suite.mock.ExpectExec("UPDATE `assets`").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "%Ubuntu%", "%Ubuntu%", "Server", "%Ubuntu%", "%Ubuntu%", "Server").
		WillReturnResult(sqlmock.NewResult(3, 3))

	suite.mock.ExpectCommit()

	// Act
	affected, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 3, affected)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_DeleteAssets_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	params := domain.NewDeleteParamsWithUUID(assetID)

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock database error
	suite.mock.ExpectExec("UPDATE `assets`").
		WillReturnError(sql.ErrConnDone)

	suite.mock.ExpectRollback()

	// Act
	affected, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, 0, affected)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for GetByFilter method
func TestAssetRepository_GetByFilter_WithPagination(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{
		OSName: "Ubuntu",
	}
	limit := 10
	offset := 0

	// Mock count query
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs("%Ubuntu%", "%Ubuntu%").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(25))

	// Mock main query with pagination
	assetID := uuid.New()
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at", "deleted_at",
	}).AddRow(assetID.String(), "Test Asset", "test.local", "test-host",
		"Ubuntu", "20.04", "Test description", "Server", 1, false,
		100, suite.now, suite.now, nil)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs("%Ubuntu%", "%Ubuntu%", limit).
		WillReturnRows(assetRows)

	// Mock asset IPs query
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Mock ports query
	suite.mock.ExpectQuery("SELECT \\* FROM `ports`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "port", "protocol", "service", "created_at", "updated_at", "deleted_at"}))

	// Mock VMware VMs query
	suite.mock.ExpectQuery("SELECT \\* FROM `vmware_vms`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "vm_id", "vm_name", "created_at", "updated_at"}))

	// Mock scanner types query
	suite.mock.ExpectQuery("SELECT asj\\.asset_id, scanners\\.scan_type FROM asset_scan_jobs asj").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"asset_id", "scan_type"}))

	// Act
	assets, total, err := suite.repo.GetByFilter(suite.ctx, filters, limit, offset)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, 25, total)
	assert.Equal(t, "Test Asset", assets[0].Name)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetByFilter_WithSorting(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{}
	limit := 10
	offset := 0
	sortOptions := []domain.SortOption{
		{Field: "name", Order: "ASC"},
	}

	// Mock count query
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock main query with sorting
	assetID := uuid.New()
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at", "deleted_at",
	}).AddRow(assetID.String(), "Asset A", "test.local", "test-host",
		"Ubuntu", "20.04", "Test description", "Server", 1, false,
		100, suite.now, suite.now, nil)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(limit).
		WillReturnRows(assetRows)

	// Mock preload queries for asset relationships
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	suite.mock.ExpectQuery("SELECT \\* FROM `ports`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "port", "protocol", "service", "created_at", "updated_at", "deleted_at"}))

	suite.mock.ExpectQuery("SELECT \\* FROM `vmware_vms`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "vm_id", "vm_name", "created_at", "updated_at"}))

	// Mock scanner types query
	suite.mock.ExpectQuery("SELECT asj").
		WillReturnRows(sqlmock.NewRows([]string{"asset_id", "scan_type"}))

	// Act
	assets, total, err := suite.repo.GetByFilter(suite.ctx, filters, limit, offset, sortOptions...)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, 1, total)
	assert.Equal(t, "Asset A", assets[0].Name)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for GetByIDsWithSort method
func TestAssetRepository_GetByIDsWithSort_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID1 := uuid.New()
	assetID2 := uuid.New()
	assetUUIDs := []domain.AssetUUID{assetID1, assetID2}
	sortOptions := []domain.SortOption{
		{Field: "name", Order: "DESC"},
	}

	// Mock the main query with sorting
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at", "deleted_at",
	}).
		AddRow(assetID2.String(), "Asset Z", "test.local", "host2",
			"Windows", "2019", "Test description 2", "Server", 2, false,
			200, suite.now, suite.now, nil).
		AddRow(assetID1.String(), "Asset A", "test.local", "host1",
			"Ubuntu", "20.04", "Test description 1", "Server", 1, false,
			100, suite.now, suite.now, nil)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetID1.String(), assetID2.String()).
		WillReturnRows(assetRows)

	// Mock preload queries that happen after the main query
	// 1. Asset IPs preload
	assetIPRows := sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "created_at", "updated_at", "deleted_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs(assetID2.String(), assetID1.String()).
		WillReturnRows(assetIPRows)

	// 2. Ports preload
	portRows := sqlmock.NewRows([]string{"id", "asset_id", "port_number", "protocol", "service", "created_at", "updated_at", "deleted_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `ports`").
		WithArgs(assetID2.String(), assetID1.String()).
		WillReturnRows(portRows)

	// 3. VMware VMs preload
	vmRows := sqlmock.NewRows([]string{"id", "asset_id", "vm_id", "vm_name", "hypervisor", "cpu_count", "memory_mb", "power_state", "created_at", "updated_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `vmware_vms`").
		WithArgs(assetID2.String(), assetID1.String()).
		WillReturnRows(vmRows)

	// 4. Scanner types query
	scannerRows := sqlmock.NewRows([]string{"asset_id", "scan_type"}).
		AddRow(assetID1.String(), "nmap").
		AddRow(assetID2.String(), "vcenter")

	suite.mock.ExpectQuery("SELECT asj\\.asset_id, scanners\\.scan_type FROM asset_scan_jobs asj").
		WithArgs(assetID2.String(), assetID1.String()).
		WillReturnRows(scannerRows)

	// Act
	assets, err := suite.repo.GetByIDsWithSort(suite.ctx, assetUUIDs, sortOptions...)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 2)
	assert.Equal(t, "Asset Z", assets[0].Name) // Should be sorted DESC by name
	assert.Equal(t, "Asset A", assets[1].Name)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for ExportAssets method
func TestAssetRepository_ExportAssets_FullExport(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	assetIDs := []domain.AssetUUID{assetID}
	exportType := domain.FullExport
	selectedColumns := []string{}

	// Mock assets query
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at",
	}).AddRow(assetID.String(), "Test Asset", "test.local", "test-host",
		"Ubuntu", "20.04", "Test description", "Server", 1, false,
		100, suite.now, suite.now)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetID.String()).
		WillReturnRows(assetRows)

	// Mock ports query
	portRows := sqlmock.NewRows([]string{
		"id", "asset_id", "port_number", "protocol", "state",
		"service_name", "service_version", "description", "discovered_at",
	}).AddRow(uuid.New().String(), assetID.String(), 80, "TCP", "Up",
		"http", "1.0", "Web server", suite.now)

	suite.mock.ExpectQuery("SELECT ports\\.\\* FROM `ports`").
		WithArgs(assetID.String()).
		WillReturnRows(portRows)

	// Mock VMware VMs query
	vmRows := sqlmock.NewRows([]string{
		"vm_id", "asset_id", "vm_name", "hypervisor", "cpu_count",
		"memory_mb", "disk_size_gb", "power_state", "last_synced_at",
	}).AddRow("vm-123", assetID.String(), "Test VM", "ESXi", 4,
		8192, 100, "On", suite.now)

	suite.mock.ExpectQuery("SELECT vmware_vms\\.\\* FROM `vmware_vms`").
		WithArgs(assetID.String()).
		WillReturnRows(vmRows)

	// Mock asset IPs query
	ipRows := sqlmock.NewRows([]string{
		"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at",
	}).AddRow(uuid.New().String(), assetID.String(), "192.168.1.100",
		"00:11:22:33:44:55", suite.now, suite.now)

	suite.mock.ExpectQuery("SELECT ips\\.\\* FROM `ips`").
		WithArgs(assetID.String()).
		WillReturnRows(ipRows)

	// Act
	exportData, err := suite.repo.ExportAssets(suite.ctx, assetIDs, exportType, selectedColumns)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, exportData)
	assert.Len(t, exportData.Assets, 1)
	assert.Len(t, exportData.Ports, 1)
	assert.Len(t, exportData.VMwareVMs, 1)
	assert.Len(t, exportData.AssetIPs, 1)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_ExportAssets_SelectedColumns(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	assetIDs := []domain.AssetUUID{assetID}
	exportType := domain.SelectedColumnsExport
	selectedColumns := []string{"assets.name", "assets.hostname", "ports.port_number"}

	// Mock assets query with selected columns
	assetRows := sqlmock.NewRows([]string{"name", "hostname", "id"}).
		AddRow("Test Asset", "test-host", assetID.String())

	suite.mock.ExpectQuery("SELECT name,hostname,id FROM `assets`").
		WithArgs(assetID.String()).
		WillReturnRows(assetRows)

	// Mock ports query with selected columns
	portRows := sqlmock.NewRows([]string{"port_number", "asset_id"}).
		AddRow(80, assetID.String())

	suite.mock.ExpectQuery("SELECT ports\\.port_number, ports\\.asset_id FROM `ports` LEFT JOIN assets").
		WithArgs(assetID.String()).
		WillReturnRows(portRows)

	// Act
	exportData, err := suite.repo.ExportAssets(suite.ctx, assetIDs, exportType, selectedColumns)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, exportData)
	assert.Len(t, exportData.Assets, 1)
	assert.Len(t, exportData.Ports, 1)
	assert.Len(t, exportData.VMwareVMs, 0) // No VMware columns selected
	assert.Len(t, exportData.AssetIPs, 0)  // No IP columns selected
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_ExportAssets_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	assetIDs := []domain.AssetUUID{assetID}
	exportType := domain.FullExport

	// Mock database error
	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetID.String()).
		WillReturnError(sql.ErrConnDone)

	// Act
	exportData, err := suite.repo.ExportAssets(suite.ctx, assetIDs, exportType, []string{})

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, exportData)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for GetDistinctOSNames method
func TestAssetRepository_GetDistinctOSNames_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	expectedOSNames := []string{"CentOS", "Ubuntu", "Windows Server"}

	osRows := sqlmock.NewRows([]string{"os_name"}).
		AddRow("CentOS").
		AddRow("Ubuntu").
		AddRow("Windows Server")

	suite.mock.ExpectQuery("SELECT DISTINCT os_name FROM `assets`").
		WillReturnRows(osRows)

	// Act
	osNames, err := suite.repo.GetDistinctOSNames(suite.ctx)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, osNames, 3)
	assert.Equal(t, expectedOSNames, osNames)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetDistinctOSNames_EmptyResult(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	osRows := sqlmock.NewRows([]string{"os_name"})

	suite.mock.ExpectQuery("SELECT DISTINCT os_name FROM `assets`").
		WillReturnRows(osRows)

	// Act
	osNames, err := suite.repo.GetDistinctOSNames(suite.ctx)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, osNames, 0)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetDistinctOSNames_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock database error
	suite.mock.ExpectQuery("SELECT DISTINCT os_name FROM `assets`").
		WillReturnError(sql.ErrConnDone)

	// Act
	osNames, err := suite.repo.GetDistinctOSNames(suite.ctx)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, osNames)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}
