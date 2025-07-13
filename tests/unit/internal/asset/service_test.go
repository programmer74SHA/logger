package asset_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	domainFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/domain"
	repoMocks "gitlab.apk-group.net/siem/backend/asset-discovery/tests/mocks/repo"
)

func TestAssetService_CreateAsset(t *testing.T) {
	tests := []struct {
		name           string
		inputAsset     domain.AssetDomain
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, assetID domain.AssetUUID, err error)
	}{
		{
			name:       "successful asset creation",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), mock.Anything).
					Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "asset creation with ports",
			inputAsset: domainFixtures.NewTestAssetDomainWithPorts(3),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify business logic: ports should be associated with asset
					return len(asset.Ports) == 3 &&
						asset.Ports[0].AssetID == asset.ID.String()
				}), mock.Anything).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "asset creation with IPs",
			inputAsset: domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.1", "10.0.0.1"}),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify business logic: IPs should be associated with asset
					return len(asset.AssetIPs) == 2 &&
						asset.AssetIPs[0].AssetID == asset.ID.String() &&
						asset.AssetIPs[1].AssetID == asset.ID.String()
				}), mock.Anything).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "IP already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateIP("192.168.1.100"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), mock.Anything).
					Return(uuid.Nil, domain.ErrIPAlreadyExists)
			},
			expectedError: domain.ErrIPAlreadyExists,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrIPAlreadyExists, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "hostname already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateHostname("existing-host"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), mock.Anything).
					Return(uuid.Nil, domain.ErrHostnameAlreadyExists)
			},
			expectedError: domain.ErrHostnameAlreadyExists,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrHostnameAlreadyExists, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "repository error mapped to service error",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), mock.Anything).
					Return(uuid.Nil, errors.New("database connection failed"))
			},
			expectedError: asset.ErrAssetCreateFailed,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetCreateFailed, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "minimal asset creation",
			inputAsset: domainFixtures.NewTestAssetDomainMinimal(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify minimal requirements are met
					return asset.Hostname == "minimal-host" &&
						asset.Type == "Server" &&
						len(asset.Ports) == 0 &&
						len(asset.AssetIPs) == 0
				}), mock.Anything).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service with mock repository
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			assetID, err := service.CreateAsset(ctx, tt.inputAsset)

			// Assert
			tt.validateResult(t, assetID, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_BusinessLogic(t *testing.T) {
	tests := []struct {
		name          string
		setupAsset    func() domain.AssetDomain
		validateLogic func(t *testing.T, asset domain.AssetDomain)
	}{
		{
			name: "asset ID consistency across ports and IPs",
			setupAsset: func() domain.AssetDomain {
				asset := domainFixtures.NewTestAssetDomain()
				asset.Ports = []domain.Port{
					domainFixtures.NewTestPort(asset.ID.String(), 80),
					domainFixtures.NewTestPort(asset.ID.String(), 443),
				}
				asset.AssetIPs = []domain.AssetIP{
					{AssetID: asset.ID.String(), IP: "192.168.1.1", MACAddress: "00:11:22:33:44:55"},
				}
				return asset
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				// All ports should have the same asset ID
				for _, port := range asset.Ports {
					assert.Equal(t, asset.ID.String(), port.AssetID)
				}
				// All IPs should have the same asset ID
				for _, ip := range asset.AssetIPs {
					assert.Equal(t, asset.ID.String(), ip.AssetID)
				}
			},
		},
		{
			name: "timestamp validation",
			setupAsset: func() domain.AssetDomain {
				return domainFixtures.NewTestAssetDomain()
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				assert.False(t, asset.CreatedAt.IsZero())
				assert.False(t, asset.UpdatedAt.IsZero())
				// CreatedAt should be before or equal to UpdatedAt
				assert.True(t, asset.CreatedAt.Before(asset.UpdatedAt) || asset.CreatedAt.Equal(asset.UpdatedAt))
			},
		},
		{
			name: "default values validation",
			setupAsset: func() domain.AssetDomain {
				return domainFixtures.NewTestAssetDomainMinimal()
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				// Required fields should be set
				assert.NotEmpty(t, asset.Hostname)
				assert.NotEmpty(t, asset.Type)
				assert.NotEqual(t, uuid.Nil, asset.ID)

				// Optional fields can be empty/zero values
				assert.Equal(t, "", asset.Name)
				assert.Equal(t, "", asset.Domain)
				assert.Equal(t, 0, asset.Risk)
				assert.Equal(t, false, asset.LoggingCompleted)
			},
		},
		{
			name: "asset with maximum complexity",
			setupAsset: func() domain.AssetDomain {
				asset := domainFixtures.NewTestAssetDomain()
				// Add multiple ports
				for i := 0; i < 10; i++ {
					asset.Ports = append(asset.Ports, domainFixtures.NewTestPort(asset.ID.String(), 80+i))
				}
				// Add multiple IPs
				for i := 0; i < 5; i++ {
					asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
						AssetID:    asset.ID.String(),
						IP:         fmt.Sprintf("192.168.1.%d", i+1),
						MACAddress: domainFixtures.NewTestMACAddress(i),
					})
				}
				return asset
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				assert.Equal(t, 10, len(asset.Ports))
				assert.Equal(t, 5, len(asset.AssetIPs))

				// Verify all relationships are correct
				for _, port := range asset.Ports {
					assert.Equal(t, asset.ID.String(), port.AssetID)
				}
				for _, ip := range asset.AssetIPs {
					assert.Equal(t, asset.ID.String(), ip.AssetID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			assetDomain := tt.setupAsset()

			// Validate business logic
			tt.validateLogic(t, assetDomain)

			// Setup mock repo for service test
			mockRepo := new(repoMocks.MockAssetRepo)
			expectedID := uuid.New()
			mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), mock.Anything).
				Return(expectedID, nil)

			// Create service and test
			service := asset.NewAssetService(mockRepo)
			ctx := context.Background()

			resultID, err := service.CreateAsset(ctx, assetDomain)

			assert.NoError(t, err)
			assert.Equal(t, expectedID, resultID)
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name            string
		repositoryError error
		expectedError   error
		errorMessage    string
	}{
		{
			name:            "IP already exists should pass through",
			repositoryError: domain.ErrIPAlreadyExists,
			expectedError:   domain.ErrIPAlreadyExists,
			errorMessage:    "IP address already exists",
		},
		{
			name:            "hostname already exists should pass through",
			repositoryError: domain.ErrHostnameAlreadyExists,
			expectedError:   domain.ErrHostnameAlreadyExists,
			errorMessage:    "Hostname already exists",
		},
		{
			name:            "database connection error should map to create failed",
			repositoryError: errors.New("database connection failed"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
		{
			name:            "transaction rollback error should map to create failed",
			repositoryError: errors.New("transaction rollback failed"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
		{
			name:            "constraint violation should map to create failed",
			repositoryError: errors.New("constraint violation"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), mock.Anything).
				Return(uuid.Nil, tt.repositoryError)

			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			testAsset := domainFixtures.NewTestAssetDomain()

			assetID, err := service.CreateAsset(ctx, testAsset)

			// Assert
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, uuid.Nil, assetID)

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent creation with same hostname should fail for second attempt", func(t *testing.T) {
		mockRepo := new(repoMocks.MockAssetRepo)

		// First call succeeds
		firstID := uuid.New()
		mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
			return asset.Hostname == "concurrent-host"
		}), mock.Anything).Return(firstID, nil).Once()

		// Second call fails with hostname already exists
		mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
			return asset.Hostname == "concurrent-host"
		}), mock.Anything).Return(uuid.Nil, domain.ErrHostnameAlreadyExists).Once()

		service := asset.NewAssetService(mockRepo)
		ctx := context.Background()

		// First asset creation
		asset1 := domainFixtures.NewTestAssetDomainWithDuplicateHostname("concurrent-host")
		resultID1, err1 := service.CreateAsset(ctx, asset1)

		assert.NoError(t, err1)
		assert.Equal(t, firstID, resultID1)

		// Second asset creation with same hostname
		asset2 := domainFixtures.NewTestAssetDomainWithDuplicateHostname("concurrent-host")
		resultID2, err2 := service.CreateAsset(ctx, asset2)

		assert.Error(t, err2)
		assert.Equal(t, domain.ErrHostnameAlreadyExists, err2)
		assert.Equal(t, uuid.Nil, resultID2)

		mockRepo.AssertExpectations(t)
	})
}

func TestAssetService_GetByID(t *testing.T) {
	tests := []struct {
		name           string
		assetUUID      domain.AssetUUID
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, result *domain.AssetDomain, err error)
	}{
		{
			name:      "successful asset retrieval",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAsset := domainFixtures.NewTestAssetDomain()
				testAsset.ID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return([]domain.AssetDomain{testAsset}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", result.ID.String())
			},
		},
		{
			name:      "asset not found - empty result",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return([]domain.AssetDomain{}, nil)
			},
			expectedError: asset.ErrAssetNotFound,
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetNotFound, err)
				assert.Nil(t, result)
			},
		},
		{
			name:      "asset not found - nil result",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return(nil, nil)
			},
			expectedError: asset.ErrAssetNotFound,
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetNotFound, err)
				assert.Nil(t, result)
			},
		},
		{
			name:      "repository error",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.GetByID(ctx, tt.assetUUID)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetByIDs(t *testing.T) {
	tests := []struct {
		name           string
		assetUUIDs     []domain.AssetUUID
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, result []domain.AssetDomain, err error)
	}{
		{
			name: "successful multiple assets retrieval",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
					domainFixtures.NewTestAssetDomain(),
				}
				testAssets[0].ID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				testAssets[1].ID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440001")
				mockRepo.On("GetByIDs", mock.Anything, mock.AnythingOfType("[]uuid.UUID")).
					Return(testAssets, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 2)
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", result[0].ID.String())
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440001", result[1].ID.String())
			},
		},
		{
			name:       "empty UUIDs list",
			assetUUIDs: []domain.AssetUUID{},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{}).
					Return([]domain.AssetDomain{}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 0)
			},
		},
		{
			name: "repository error",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, mock.AnythingOfType("[]uuid.UUID")).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.GetByIDs(ctx, tt.assetUUIDs)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_Get(t *testing.T) {
	tests := []struct {
		name           string
		filter         domain.AssetFilters
		limit          int
		offset         int
		sortOptions    []domain.SortOption
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, assets []domain.AssetDomain, total int, err error)
	}{
		{
			name: "successful assets retrieval with filters",
			filter: domain.AssetFilters{
				Name:     "test",
				Hostname: "test-host",
			},
			limit:  10,
			offset: 0,
			sortOptions: []domain.SortOption{
				{Field: "name", Order: "asc"},
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
					domainFixtures.NewTestAssetDomain(),
				}
				mockRepo.On("GetByFilter", mock.Anything,
					mock.MatchedBy(func(filter domain.AssetFilters) bool {
						return filter.Name == "test" && filter.Hostname == "test-host"
					}),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 15, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assets []domain.AssetDomain, total int, err error) {
				assert.NoError(t, err)
				assert.Len(t, assets, 2)
				assert.Equal(t, 15, total)
			},
		},
		{
			name:        "empty filter returns all assets",
			filter:      domain.AssetFilters{},
			limit:       5,
			offset:      10,
			sortOptions: []domain.SortOption{},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
				}
				mockRepo.On("GetByFilter", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					5, 10, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 100, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assets []domain.AssetDomain, total int, err error) {
				assert.NoError(t, err)
				assert.Len(t, assets, 1)
				assert.Equal(t, 100, total)
			},
		},
		{
			name:   "repository error",
			filter: domain.AssetFilters{},
			limit:  10,
			offset: 0,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByFilter", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(nil, 0, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, assets []domain.AssetDomain, total int, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, assets)
				assert.Equal(t, 0, total)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			assets, total, err := service.Get(ctx, tt.filter, tt.limit, tt.offset, tt.sortOptions...)

			// Validate
			tt.validateResult(t, assets, total, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_UpdateAsset(t *testing.T) {
	tests := []struct {
		name           string
		inputAsset     domain.AssetDomain
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, err error)
	}{
		{
			name:       "successful asset update",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:       "asset update with ports and IPs",
			inputAsset: domainFixtures.NewTestAssetDomainWithPorts(2),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					return len(asset.Ports) == 2
				})).Return(nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:       "IP already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateIP("192.168.1.100"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(domain.ErrIPAlreadyExists)
			},
			expectedError: domain.ErrIPAlreadyExists,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrIPAlreadyExists, err)
			},
		},
		{
			name:       "repository error mapped to service error",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(errors.New("database connection failed"))
			},
			expectedError: asset.ErrAssetUpdateFailed,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetUpdateFailed, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			err := service.UpdateAsset(ctx, tt.inputAsset)

			// Validate
			tt.validateResult(t, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_DeleteAssets(t *testing.T) {
	tests := []struct {
		name           string
		ids            []string
		filter         *domain.AssetFilters
		exclude        bool
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, err error)
	}{
		{
			name: "successful single asset deletion",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.UUID != nil && params.UUID.String() == "550e8400-e29b-41d4-a716-446655440000"
				})).Return(1, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "successful multiple assets deletion",
			ids: []string{
				"550e8400-e29b-41d4-a716-446655440000",
				"550e8400-e29b-41d4-a716-446655440001",
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return len(params.UUIDs) == 2
				})).Return(2, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "delete all assets",
			ids:     []string{"All"},
			exclude: false,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.UUID == nil && len(params.UUIDs) == 0 && params.Filters == nil
				})).Return(10, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "delete with filter",
			ids:  []string{"All"},
			filter: &domain.AssetFilters{
				Name: "test",
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.Filters != nil && params.Filters.Name == "test"
				})).Return(5, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "delete all except specified IDs",
			ids:     []string{"550e8400-e29b-41d4-a716-446655440000"},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.Exclude && len(params.UUIDs) == 1
				})).Return(8, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "invalid UUID format",
			ids:  []string{"invalid-uuid"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
		{
			name: "no assets found for deletion",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.AnythingOfType("domain.DeleteParams")).
					Return(0, nil)
			},
			expectedError: asset.ErrAssetNotFound,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetNotFound, err)
			},
		},
		{
			name: "repository error",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.AnythingOfType("domain.DeleteParams")).
					Return(0, errors.New("database connection failed"))
			},
			expectedError: asset.ErrAssetDeleteFailed,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetDeleteFailed, err)
			},
		},
		{
			name: "empty IDs list should not delete anything",
			ids:  []string{},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as service should return early
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "multiple invalid UUID formats in list",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000", "invalid-uuid", "another-invalid"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail on second ID
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
		{
			name: "delete with filter and specific IDs (both conditions)",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001"},
			filter: &domain.AssetFilters{
				Name: "test-asset",
			},
			exclude: false,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return len(params.UUIDs) == 2 &&
						params.Filters != nil &&
						params.Filters.Name == "test-asset" &&
						!params.Exclude
				})).Return(2, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "delete with filter excluding specific IDs",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001"},
			filter: &domain.AssetFilters{
				Name: "test-asset",
			},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return len(params.UUIDs) == 2 &&
						params.Filters != nil &&
						params.Filters.Name == "test-asset" &&
						params.Exclude
				})).Return(3, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "exclude with empty IDs list (delete all)",
			ids:     []string{},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.UUID == nil &&
						len(params.UUIDs) == 0 &&
						params.Filters == nil &&
						!params.Exclude
				})).Return(15, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "invalid UUID in multiple IDs scenario with exclude",
			ids:     []string{"550e8400-e29b-41d4-a716-446655440000", "invalid-uuid"},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
		{
			name: "delete with filter and invalid UUID",
			ids:  []string{"invalid-uuid"},
			filter: &domain.AssetFilters{
				Name: "test-asset",
			},
			exclude: false,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			err := service.DeleteAssets(ctx, tt.ids, tt.filter, tt.exclude)

			// Validate
			tt.validateResult(t, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_ExportAssets(t *testing.T) {
	tests := []struct {
		name            string
		assetIDs        []domain.AssetUUID
		exportType      domain.ExportType
		selectedColumns []string
		setupMock       func(*repoMocks.MockAssetRepo)
		expectedError   error
		validateResult  func(t *testing.T, result *domain.ExportData, err error)
	}{
		{
			name: "successful CSV export",
			assetIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			exportType:      domain.FullExport,
			selectedColumns: []string{"name", "hostname", "ip"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				exportData := &domain.ExportData{
					Assets: []map[string]interface{}{
						{"name": "Test Asset", "hostname": "test-host", "ip": "192.168.1.1"},
					},
					AssetIPs:  []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
				}
				mockRepo.On("ExportAssets", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					domain.FullExport,
					[]string{"name", "hostname", "ip"}).
					Return(exportData, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.ExportData, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Assets, 1)
				assert.Equal(t, "Test Asset", result.Assets[0]["name"])
			},
		},
		{
			name:            "empty asset IDs list",
			assetIDs:        []domain.AssetUUID{},
			exportType:      domain.SelectedColumnsExport,
			selectedColumns: []string{"name"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				exportData := &domain.ExportData{
					Assets:    []map[string]interface{}{},
					AssetIPs:  []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
				}
				mockRepo.On("ExportAssets", mock.Anything,
					[]domain.AssetUUID{},
					domain.SelectedColumnsExport,
					[]string{"name"}).
					Return(exportData, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.ExportData, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Assets, 0)
			},
		},
		{
			name: "repository error",
			assetIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			exportType:      domain.FullExport,
			selectedColumns: []string{"name"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("ExportAssets", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					domain.FullExport,
					[]string{"name"}).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: asset.ErrExportFailed,
			validateResult: func(t *testing.T, result *domain.ExportData, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrExportFailed, err)
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.ExportAssets(ctx, tt.assetIDs, tt.exportType, tt.selectedColumns)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_GenerateCSV(t *testing.T) {
	tests := []struct {
		name           string
		exportData     *domain.ExportData
		expectedError  error
		validateResult func(t *testing.T, csvData []byte, err error)
	}{
		{
			name: "successful CSV generation",
			exportData: &domain.ExportData{
				Assets: []map[string]interface{}{
					{"name": "Test Asset 1", "hostname": "test-host-1", "ip": "192.168.1.1"},
					{"name": "Test Asset 2", "hostname": "test-host-2", "ip": "192.168.1.2"},
				},
				AssetIPs:  []map[string]interface{}{},
				VMwareVMs: []map[string]interface{}{},
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, csvData)
				assert.Greater(t, len(csvData), 0)
				csvString := string(csvData)
				assert.Contains(t, csvString, "Test Asset 1")
				assert.Contains(t, csvString, "test-host-1")
			},
		},
		{
			name: "CSV generation with status field",
			exportData: &domain.ExportData{
				Assets: []map[string]interface{}{
					{"status": "active", "name": "Test Asset", "hostname": "test-host"},
				},
				AssetIPs:  []map[string]interface{}{},
				VMwareVMs: []map[string]interface{}{},
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, csvData)
				csvString := string(csvData)
				assert.Contains(t, csvString, "status")
				assert.Contains(t, csvString, "active")
			},
		},
		{
			name:          "nil export data",
			exportData:    nil,
			expectedError: fmt.Errorf("export data is nil"),
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "export data is nil")
				assert.Nil(t, csvData)
			},
		},
		{
			name: "empty export data",
			exportData: &domain.ExportData{
				Assets:    []map[string]interface{}{},
				AssetIPs:  []map[string]interface{}{},
				VMwareVMs: []map[string]interface{}{},
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, csvData)
				// Should contain at least headers
				assert.Greater(t, len(csvData), 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			csvData, err := service.GenerateCSV(ctx, tt.exportData)

			// Validate
			tt.validateResult(t, csvData, err)
		})
	}
}

func TestAssetService_GetDistinctOSNames(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, osNames []string, err error)
	}{
		{
			name: "successful OS names retrieval",
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				osNames := []string{"Ubuntu", "Windows Server", "CentOS", "Red Hat"}
				mockRepo.On("GetDistinctOSNames", mock.Anything).
					Return(osNames, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, osNames []string, err error) {
				assert.NoError(t, err)
				assert.Len(t, osNames, 4)
				assert.Contains(t, osNames, "Ubuntu")
				assert.Contains(t, osNames, "Windows Server")
				assert.Contains(t, osNames, "CentOS")
				assert.Contains(t, osNames, "Red Hat")
			},
		},
		{
			name: "empty OS names list",
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetDistinctOSNames", mock.Anything).
					Return([]string{}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, osNames []string, err error) {
				assert.NoError(t, err)
				assert.Len(t, osNames, 0)
			},
		},
		{
			name: "repository error",
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetDistinctOSNames", mock.Anything).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: asset.ErrOSNamesFailed,
			validateResult: func(t *testing.T, osNames []string, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrOSNamesFailed, err)
				assert.Nil(t, osNames)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			osNames, err := service.GetDistinctOSNames(ctx)

			// Validate
			tt.validateResult(t, osNames, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetByIDsWithSort(t *testing.T) {
	tests := []struct {
		name           string
		assetUUIDs     []domain.AssetUUID
		sortOptions    []domain.SortOption
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, result []domain.AssetDomain, err error)
	}{
		{
			name: "successful sorted assets retrieval",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			},
			sortOptions: []domain.SortOption{
				{Field: "name", Order: "asc"},
				{Field: "created_at", Order: "desc"},
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
					domainFixtures.NewTestAssetDomain(),
				}
				testAssets[0].Name = "Asset A"
				testAssets[1].Name = "Asset B"
				mockRepo.On("GetByIDsWithSort", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					mock.MatchedBy(func(sorts []domain.SortOption) bool {
						return len(sorts) == 2 &&
							sorts[0].Field == "name" && sorts[0].Order == "asc" &&
							sorts[1].Field == "created_at" && sorts[1].Order == "desc"
					})).Return(testAssets, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 2)
				assert.Equal(t, "Asset A", result[0].Name)
				assert.Equal(t, "Asset B", result[1].Name)
			},
		},
		{
			name:       "empty UUIDs with sort options",
			assetUUIDs: []domain.AssetUUID{},
			sortOptions: []domain.SortOption{
				{Field: "name", Order: "asc"},
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDsWithSort", mock.Anything,
					[]domain.AssetUUID{},
					mock.AnythingOfType("[]domain.SortOption")).
					Return([]domain.AssetDomain{}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 0)
			},
		},
		{
			name: "repository error",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			sortOptions: []domain.SortOption{},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDsWithSort", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					mock.AnythingOfType("[]domain.SortOption")).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.GetByIDsWithSort(ctx, tt.assetUUIDs, tt.sortOptions...)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}
