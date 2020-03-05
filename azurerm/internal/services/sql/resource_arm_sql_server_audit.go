package sql

import (
	"fmt"
	"github.com/satori/go.uuid"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/preview/sql/mgmt/2017-03-01-preview/sql"
	"github.com/hashicorp/go-azure-helpers/response"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/features"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tags"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/timeouts"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceArmSqlServerAudit() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmSqlServerAuditCreateUpdate,
		Read:   resourceArmSqlServerAuditRead,
		Update: resourceArmSqlServerAuditCreateUpdate,
		Delete: resourceArmSqlServerAuditDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(60 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(60 * time.Minute),
			Delete: schema.DefaultTimeout(60 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"audit_actions_and_groups": {
				Type:         schema.TypeList,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.ListOfUniqueStrings,
			},
			"monitor_target_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
			},
			"server_name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: azure.ValidateMsSqlServerName,
			},
			"is_secondary_storage_key": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"queue_delay": {
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1000, 2147483647),
			},
			"resource_group_name": azure.SchemaResourceGroupName(),
			"retention_days": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  30,
			},
			"access_key": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"subscription_id": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"storage_endpoint": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
		},
	}
}

func resourceArmSqlServerAuditCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).Sql.ServerAuditsClient
	ctx, cancel := timeouts.ForCreateUpdate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	serverName := d.Get("server_name").(string)
	resGroup := d.Get("resource_group_name").(string)

	if features.ShouldResourcesBeImported() && d.IsNewResource() {
		existing, err := client.Get(ctx, resGroup, serverName)
		if err != nil {
			if !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("Error checking for presence of existing SQL Server %q (Resource Group %q): %+v", serverName, resGroup, err)
			}
		}

		if existing.ID != nil && *existing.ID != "" {
			return tf.ImportAsExistsError("azurerm_sql_server", *existing.ID)
		}
	}

	parameters := sql.ServerBlobAuditingPolicy{
		ServerBlobAuditingPolicyProperties: &sql.ServerBlobAuditingPolicyProperties{
			State:                        "Enabled",
			AuditActionsAndGroups:        nil,
		},
	}

	if v, ok := d.GetOk("monitor_target_enabled"); ok {
		isMonitorTargetEnabled := v.(bool)
		parameters.IsAzureMonitorTargetEnabled = &isMonitorTargetEnabled
	}

	if v, ok := d.GetOk("queue_delay"); ok {
		queueDelay := v.(int32)
		parameters.QueueDelayMs = &queueDelay
	}

	if v, ok := d.GetOk("access_key"); ok {
		accessKey := v.(string)
		parameters.StorageAccountAccessKey = &accessKey
	}

	if v, ok := d.GetOk("subscription_id"); ok {
		subscriptionId := v.(uuid.UUID)
		parameters.StorageAccountSubscriptionID = &subscriptionId
	}

	if v, ok := d.GetOk("storage_endpoint"); ok {
		storageEndpoint := v.(string)
		parameters.StorageEndpoint = &storageEndpoint
	}

	if v, ok := d.GetOk("retention_days"); ok {
		retentionDays := v.(int32)
		parameters.RetentionDays = &retentionDays
	}

	if v, ok := d.GetOk("audit_actions_and_groups"); ok {
		actionsAndGroups := v.([]string)
		parameters.AuditActionsAndGroups = &actionsAndGroups
	}

	future, err := client.CreateOrUpdate(ctx, resGroup, serverName, parameters)
	if err != nil {
		return fmt.Errorf("Error issuing create/update request for SQL Server Audit Rule %q (Resource Group %q): %+v", serverName, resGroup, err)
	}

	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		if response.WasConflict(future.Response()) {
			return fmt.Errorf("SQL Server names need to be globally unique and %q is already in use.", serverName)
		}

		return fmt.Errorf("Error waiting on create/update future for SQL Server %q (Resource Group %q): %+v", serverName, resGroup, err)
	}

	resp, err := client.Get(ctx, resGroup, serverName)
	if err != nil {
		return fmt.Errorf("Error issuing get request for SQL Server %q (Resource Group %q): %+v", serverName, resGroup, err)
	}

	d.SetId(*resp.ID)

	return resourceArmSqlServerAuditRead(d, meta)
}

func resourceArmSqlServerAuditRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).Sql.ServersClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := azure.ParseAzureResourceID(d.Id())
	if err != nil {
		return err
	}

	resGroup := id.ResourceGroup
	name := id.Path["servers"]

	resp, err := client.Get(ctx, resGroup, name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[INFO] Error reading SQL Server %q - removing from state", d.Id())
			d.SetId("")
			return nil
		}

		return fmt.Errorf("Error reading SQL Server %s: %v", name, err)
	}

	d.Set("name", name)
	d.Set("resource_group_name", resGroup)
	if location := resp.Location; location != nil {
		d.Set("location", azure.NormalizeLocation(*location))
	}

	if err := d.Set("identity", flattenAzureRmSqlServerIdentity(resp.Identity)); err != nil {
		return fmt.Errorf("Error setting `identity`: %+v", err)
	}

	if serverProperties := resp.ServerProperties; serverProperties != nil {
		d.Set("version", serverProperties.Version)
		d.Set("administrator_login", serverProperties.AdministratorLogin)
		d.Set("fully_qualified_domain_name", serverProperties.FullyQualifiedDomainName)
	}

	return tags.FlattenAndSet(d, resp.Tags)
}

func resourceArmSqlServerAuditDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).Sql.ServersClient
	ctx, cancel := timeouts.ForDelete(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := azure.ParseAzureResourceID(d.Id())
	if err != nil {
		return err
	}

	resGroup := id.ResourceGroup
	name := id.Path["servers"]

	future, err := client.Delete(ctx, resGroup, name)
	if err != nil {
		return fmt.Errorf("Error deleting SQL Server %s: %+v", name, err)
	}

	return future.WaitForCompletionRef(ctx, client.Client)
}
