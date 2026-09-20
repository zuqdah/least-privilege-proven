output "azure_client_id" {
  value = azuread_application.deployer.client_id
}

output "azure_tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "azure_subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}

output "tfstate_resource_group" {
  value = azurerm_resource_group.tfstate.name
}

output "tfstate_storage_account" {
  value = azurerm_storage_account.tfstate.name
}

output "tfstate_container" {
  value = azurerm_storage_container.tfstate.name
}

output "lab_resource_group" {
  value = azurerm_resource_group.lab.name
}

output "subject_client_ids" {
  description = "Set as SUBJECT_CLIENT_IDS. The pipeline mints a short-lived secret for each."
  value       = jsonencode({ for k, v in azuread_application.subject : k => v.client_id })
}

output "subject_object_ids" {
  description = "Set as SUBJECT_OBJECT_IDS. infra assigns roles to these."
  value       = jsonencode({ for k, v in azuread_service_principal.subject : k => v.object_id })
}
output "custom_role_definition_id" {
  description = "Set as CUSTOM_ROLE_ID. Pinned here so the deploy identity can be constrained to assigning only this role and two built-ins."
  value       = random_uuid.custom_role.result
}

output "deployer_object_id" {
  description = "Set as DEPLOYER_OBJECT_ID. infra declares this identity's own assignments so they are not reported as drift."
  value       = azuread_service_principal.deployer.object_id
}
output "custom_role_resource_id" {
  description = "Set as CUSTOM_ROLE_RESOURCE_ID. infra assigns this role but does not define it."
  value       = azurerm_role_definition.restart_only.role_definition_resource_id
}

output "custom_role_name" {
  description = "Set as CUSTOM_ROLE_NAME. Used for drift comparison, which matches on role name."
  value       = azurerm_role_definition.restart_only.name
}