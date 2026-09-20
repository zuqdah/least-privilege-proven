terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 5.6" }
    azuread = { source = "hashicorp/azuread", version = "~> 3.9" }
    random  = { source = "hashicorp/random", version = "~> 3.9" }
  }

  # Bootstrap runs once, locally, as a subscription Owner and a directory
  # admin. Its state stays local and out of git.
}

provider "azurerm" {
  resource_providers_to_register = ["Microsoft.Storage"]
  storage_use_azuread            = true
  features {}
}

provider "azuread" {}