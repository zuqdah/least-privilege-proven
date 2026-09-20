data "azurerm_resource_group" "lab" {
  name = var.resource_group_name
}

data "azurerm_subscription" "current" {}

resource "random_string" "suffix" {
  length  = 5
  lower   = true
  upper   = false
  numeric = true
  special = false

  keepers = {
    location = coalesce(var.location, data.azurerm_resource_group.lab.location)
  }
}

locals {
  name     = "lpp-${random_string.suffix.result}"
  location = coalesce(var.location, data.azurerm_resource_group.lab.location)

  tags = merge(var.tags, {
    workload   = "least-privilege-proven"
    managed-by = "terraform"
    repo       = "github.com/zuqdah/least-privilege-proven"
  })
}

# ---------------------------------------------------------------------------
# Something for the subjects to be allowed and denied against. A storage
# account is convenient because listKeys is a genuine privilege boundary:
# Reader cannot call it, Contributor can, and the difference is exactly the
# kind of thing that gets missed in a review.
# ---------------------------------------------------------------------------

resource "azurerm_storage_account" "target" {
  #checkov:skip=CKV_AZURE_59:The account is private; public access is disabled below.
  #checkov:skip=CKV_AZURE_206:A probe target rebuilt on every run; LRS matches its value.
  #checkov:skip=CKV_AZURE_33:No queue service is used.
  #checkov:skip=CKV2_AZURE_21:Blob read logging would cost more than the target it watches.
  #checkov:skip=CKV2_AZURE_33:A private endpoint needs a runner inside the VNet; the hosted runner is not.
  #checkov:skip=CKV2_AZURE_40:Shared keys stay enabled on purpose so that listKeys is a meaningful denial to test.
  #checkov:skip=CKV2_AZURE_41:SAS policy is not what this target exists to demonstrate.
  name                            = replace("st${local.name}", "-", "")
  resource_group_name             = data.azurerm_resource_group.lab.name
  location                        = local.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false

  blob_properties {
    delete_retention_policy { days = 7 }
  }

  tags = local.tags
}

# ---------------------------------------------------------------------------
# The assignments under test
# ---------------------------------------------------------------------------

resource "azurerm_role_assignment" "reader" {
  scope                = data.azurerm_resource_group.lab.id
  role_definition_name = "Reader"
  principal_id         = var.subject_object_ids["reader"]
}

resource "azurerm_role_assignment" "operator" {
  scope              = data.azurerm_resource_group.lab.id
  role_definition_id = var.custom_role_resource_id
  principal_id       = var.subject_object_ids["operator"]
}

# Contributor can build anything in the group and cannot hand out access.
# That second half is the interesting one, and it is asserted rather than
# assumed: the proof has this identity attempt a role assignment.
resource "azurerm_role_assignment" "deployer" {
  scope                = data.azurerm_resource_group.lab.id
  role_definition_name = "Contributor"
  principal_id         = var.subject_object_ids["deployer"]
}