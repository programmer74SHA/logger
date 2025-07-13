package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gorm.io/gorm"
)

type SwitchRepo struct {
	db *gorm.DB
}

func NewSwitchRepo(db *gorm.DB) *SwitchRepo {
	return &SwitchRepo{
		db: db,
	}
}

// Core switch metadata operations
func (r *SwitchRepo) CreateSwitchMetadata(ctx context.Context, assetID string, username, password string, port int, brand string) error {
	switchMetadata := types.SwitchMetadata{
		ID:       uuid.New().String(),
		AssetID:  assetID,
		Username: username,
		Password: password,
		Port:     port,
		Brand:    brand,
	}

	return r.db.WithContext(ctx).Table("switch_metadata").Create(&switchMetadata).Error
}

func (r *SwitchRepo) GetSwitchMetadataByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) (*types.SwitchMetadata, error) {
	var switchMetadata types.SwitchMetadata
	err := r.db.WithContext(ctx).
		Table("switch_metadata").
		Where("asset_id = ?", assetID.String()).
		First(&switchMetadata).Error
	return &switchMetadata, err
}

func (r *SwitchRepo) UpdateSwitchMetadata(ctx context.Context, assetID assetDomain.AssetUUID, username, password string, port int, brand string) error {
	updates := map[string]interface{}{
		"username":   username,
		"password":   password,
		"port":       port,
		"brand":      brand,
		"updated_at": time.Now(),
	}

	return r.db.WithContext(ctx).
		Table("switch_metadata").
		Where("asset_id = ?", assetID.String()).
		Updates(updates).Error
}

func (r *SwitchRepo) DeleteSwitchMetadata(ctx context.Context, assetID assetDomain.AssetUUID) error {
	return r.db.WithContext(ctx).
		Table("switch_metadata").
		Where("asset_id = ?", assetID.String()).
		Delete(&types.SwitchMetadata{}).Error
}

// Interface operations using existing interfaces table
func (r *SwitchRepo) CreateSwitchInterface(ctx context.Context, switchInterface types.Interfaces) error {
	if switchInterface.ID == "" {
		switchInterface.ID = uuid.New().String()
	}
	return r.db.WithContext(ctx).Table("interfaces").Create(&switchInterface).Error
}

func (r *SwitchRepo) GetSwitchInterfacesByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.Interfaces, error) {
	var interfaces []types.Interfaces
	err := r.db.WithContext(ctx).
		Table("interfaces").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Find(&interfaces).Error
	return interfaces, err
}

// VLAN operations using existing vlans table
func (r *SwitchRepo) CreateSwitchVLAN(ctx context.Context, switchVLAN types.VLANs) error {
	if switchVLAN.ID == "" {
		switchVLAN.ID = uuid.New().String()
	}
	return r.db.WithContext(ctx).Table("vlans").Create(&switchVLAN).Error
}

func (r *SwitchRepo) GetSwitchVLANsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.VLANs, error) {
	var vlans []types.VLANs
	err := r.db.WithContext(ctx).
		Table("vlans").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Order("vlan_id ASC").
		Find(&vlans).Error
	return vlans, err
}

// Neighbor operations
func (r *SwitchRepo) CreateSwitchNeighbor(ctx context.Context, switchNeighbor types.SwitchNeighbor) error {
	if switchNeighbor.ID == "" {
		switchNeighbor.ID = uuid.New().String()
	}
	return r.db.WithContext(ctx).Table("switch_neighbors").Create(&switchNeighbor).Error
}

func (r *SwitchRepo) GetSwitchNeighborsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.SwitchNeighbor, error) {
	var switchNeighbors []types.SwitchNeighbor
	err := r.db.WithContext(ctx).
		Table("switch_neighbors").
		Where("switch_id = ?", assetID.String()).
		Order("local_port ASC").
		Find(&switchNeighbors).Error
	return switchNeighbors, err
}

// Cleanup operations
func (r *SwitchRepo) DeleteAllSwitchDataByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		assetIDStr := assetID.String()

		// Soft delete interfaces for this asset
		if err := tx.Table("interfaces").
			Where("asset_id = ? AND deleted_at IS NULL", assetIDStr).
			Update("deleted_at", time.Now()).Error; err != nil {
			return err
		}

		// Soft delete VLANs for this asset
		if err := tx.Table("vlans").
			Where("asset_id = ? AND deleted_at IS NULL", assetIDStr).
			Update("deleted_at", time.Now()).Error; err != nil {
			return err
		}

		// Delete switch metadata
		if err := tx.Table("switch_metadata").
			Where("asset_id = ?", assetIDStr).
			Delete(&types.SwitchMetadata{}).Error; err != nil {
			return err
		}

		// Delete switch neighbors
		if err := tx.Table("switch_neighbors").
			Where("switch_id = ?", assetIDStr).
			Delete(&types.SwitchNeighbor{}).Error; err != nil {
			return err
		}

		return nil
	})
}

// Bulk operations for better performance
func (r *SwitchRepo) BulkCreateSwitchData(ctx context.Context, assetID assetDomain.AssetUUID, data map[string]interface{}) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Create switch metadata if provided
		if metadata, ok := data["switch_metadata"].(*types.SwitchMetadata); ok && metadata != nil {
			if err := tx.Table("switch_metadata").Create(metadata).Error; err != nil {
				return err
			}
		}

		// Create interfaces if provided
		if interfaces, ok := data["interfaces"].([]types.Interfaces); ok && len(interfaces) > 0 {
			for _, intf := range interfaces {
				if intf.ID == "" {
					intf.ID = uuid.New().String()
				}
				if err := tx.Table("interfaces").Create(&intf).Error; err != nil {
					return err
				}
			}
		}

		// Create VLANs if provided
		if vlans, ok := data["vlans"].([]types.VLANs); ok && len(vlans) > 0 {
			for _, vlan := range vlans {
				if vlan.ID == "" {
					vlan.ID = uuid.New().String()
				}
				if err := tx.Table("vlans").Create(&vlan).Error; err != nil {
					return err
				}
			}
		}

		return nil
	})
}
