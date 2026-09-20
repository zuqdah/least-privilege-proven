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