variable "resource_group_name" {
  description = "Existing resource group the lab deploys into."
  type        = string
}

variable "location" {
  description = "Region override. Defaults to the resource group region."
  type        = string
  default     = null
}

variable "subject_object_ids" {
  description = "Service principal object IDs for the identities under test, keyed by role name."
  type        = map(string)
}

variable "tags" {
  description = "Tags applied to everything."
  type        = map(string)
  default     = {}
}
variable "custom_role_definition_id" {
  description = "Pinned UUID for the custom role. Bootstrap generates it so the deploy identity can be constrained to assigning only this role."
  type        = string
}

variable "deployer_object_id" {
  description = "The deploy identity. Its own assignments at this scope are declared so they are not reported as drift."
  type        = string
}