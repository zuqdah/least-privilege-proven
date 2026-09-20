output "resource_group_name" {
  value = data.azurerm_resource_group.lab.name
}

output "resource_group_id" {
  value = data.azurerm_resource_group.lab.id
}

output "storage_account_name" {
  description = "The target the subjects are allowed and denied against."
  value       = azurerm_storage_account.target.name
}

output "custom_role_name" {
  value = var.custom_role_name
}

output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}
output "declared_assignments" {
  description = "What source control says should exist at the lab scope. Drift detection compares the live assignments against this, so anything else present was granted outside code."
  value = jsonencode([
    {
      PrincipalId = var.subject_object_ids["reader"]
      RoleName    = "Reader"
      Scope       = data.azurerm_resource_group.lab.id
    },
    {
      PrincipalId = var.subject_object_ids["operator"]
      RoleName    = var.custom_role_name
      Scope       = data.azurerm_resource_group.lab.id
    },
    {
      PrincipalId = var.subject_object_ids["deployer"]
      RoleName    = "Contributor"
      Scope       = data.azurerm_resource_group.lab.id
    },
    # The deploy identity's own grants, made in bootstrap. They are declared
    # in source control just as much as the others, so leaving them out here
    # would report the pipeline itself as drift on every run.
    {
      PrincipalId = var.deployer_object_id
      RoleName    = "Contributor"
      Scope       = data.azurerm_resource_group.lab.id
    },
    {
      PrincipalId = var.deployer_object_id
      RoleName    = "Role Based Access Control Administrator"
      Scope       = data.azurerm_resource_group.lab.id
    },
  ])
}