data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}

# The custom role needs a stable id at bootstrap time so the ABAC condition
# below can name it. Generating it here and passing it to infra is what lets
# the deploy identity be constrained to exactly three roles.
resource "random_uuid" "custom_role" {}

resource "random_string" "state" {
  length  = 6
  lower   = true
  upper   = false
  numeric = true
  special = false
}

resource "azurerm_resource_group" "tfstate" {
  name     = "rg-lpp-tfstate"
  location = var.location
  tags     = { workload = "least-privilege-proven", purpose = "terraform-state" }
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-lpp-lab"
  location = var.location
  tags     = { workload = "least-privilege-proven", purpose = "lab" }
}

resource "azurerm_storage_account" "tfstate" {
  #checkov:skip=CKV_AZURE_59:The container is private and public access is disabled below.
  #checkov:skip=CKV_AZURE_206:State describes a lab rebuilt from source; LRS matches its value.
  #checkov:skip=CKV_AZURE_33:No queue service is used by this account.
  #checkov:skip=CKV2_AZURE_21:Blob read logging would exceed the value of the state it records.
  #checkov:skip=CKV2_AZURE_33:A private endpoint needs a runner inside the VNet; the hosted runner is not.
  #checkov:skip=CKV2_AZURE_40:Shared keys are disabled, so there is no key to expire.
  #checkov:skip=CKV2_AZURE_41:SAS policy is moot with local auth off.
  name                            = "stlpp${random_string.state.result}"
  resource_group_name             = azurerm_resource_group.tfstate.name
  location                        = azurerm_resource_group.tfstate.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false

  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 7 }
  }

  tags = { workload = "least-privilege-proven" }
}

resource "azurerm_storage_container" "tfstate" {
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.tfstate.id
  container_access_type = "private"
}

locals {
  tfstate_container_scope = "${azurerm_storage_account.tfstate.id}/blobServices/default/containers/${azurerm_storage_container.tfstate.name}"

  subject_environment = "repo:${split("/", var.github_repository)[0]}@${var.github_repository_owner_id}/${split("/", var.github_repository)[1]}@${var.github_repository_id}:environment:${var.github_environment}"

  # The identities under test. Each exists to be told no about something
  # specific, which is what the proof checks.
  subjects = {
    reader   = "Can look and nothing else."
    operator = "Can restart what is already running, and not create or destroy."
    deployer = "Can build infrastructure, and not hand out access."
  }
}

# ---------------------------------------------------------------------------
# Deploy identity
# ---------------------------------------------------------------------------

resource "azuread_application" "deployer" {
  display_name     = "gh-least-privilege-proven"
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "deployer" {
  client_id = azuread_application.deployer.client_id
}

resource "azuread_application_federated_identity_credential" "environment" {
  #checkov:skip=CKV_AZURE_249:The subject is deliberately the immutable ID form; the checked pattern expects the name form.
  application_id = azuread_application.deployer.id
  display_name   = "github-environment-${var.github_environment}"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = local.subject_environment
}

# ---------------------------------------------------------------------------
# Identities under test
#
# Created here, as a directory admin, rather than by the pipeline. The deploy
# identity is made an owner of each, which lets it mint a short-lived secret
# for a probe without holding tenant-wide Application.ReadWrite.All. Ownership
# of three named applications is a far smaller grant than the ability to
# create and credential any application in the directory.
# ---------------------------------------------------------------------------

resource "azuread_application" "subject" {
  for_each = local.subjects

  display_name     = "lpp-subject-${each.key}"
  sign_in_audience = "AzureADMyOrg"
  description      = each.value

  owners = [azuread_service_principal.deployer.object_id]
}

resource "azuread_service_principal" "subject" {
  for_each = local.subjects

  client_id = azuread_application.subject[each.key].client_id
  owners    = [azuread_service_principal.deployer.object_id]
}

# ---------------------------------------------------------------------------
# Deploy identity permissions: one resource group, its state, and the right to
# assign roles within that group. The proof then checks that the subjects
# cannot do the same thing.
# ---------------------------------------------------------------------------

resource "azurerm_role_assignment" "deployer_lab" {
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.deployer.object_id
}

# User Access Administrator would let this identity assign any role at the
# scope, including Owner to itself. The lab checks for exactly that, and its
# own deploy identity should not be the exception.
#
# Role Based Access Control Administrator with an ABAC condition can assign
# only the three roles this lab uses: Reader, Contributor, and the custom
# Restart Only role. The condition is what makes this delegation rather than
# self-promotion, and the escalation analysis grades it Info rather than
# Critical for precisely that reason.
resource "azurerm_role_assignment" "deployer_rbac" {
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Role Based Access Control Administrator"
  principal_id         = azuread_service_principal.deployer.object_id

  condition_version = "2.0"
  condition         = <<-COND
    (
      (
        !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
      )
      OR
      (
        @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals{acdd72a7-3385-48ef-bd42-f606fba81ae7, b24988ac-6180-42a0-ab88-20f7382dd24c, ${random_uuid.custom_role.result}}
      )
    )
    AND
    (
      (
        !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
      )
      OR
      (
        @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals{acdd72a7-3385-48ef-bd42-f606fba81ae7, b24988ac-6180-42a0-ab88-20f7382dd24c, ${random_uuid.custom_role.result}}
      )
    )
  COND
}

resource "azurerm_role_assignment" "deployer_state" {
  scope                = local.tfstate_container_scope
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azuread_service_principal.deployer.object_id
}

resource "azurerm_role_assignment" "operator_state" {
  scope                = local.tfstate_container_scope
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}