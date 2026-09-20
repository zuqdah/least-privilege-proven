terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 5.6" }
    random  = { source = "hashicorp/random", version = "~> 3.9" }
  }

  backend "azurerm" {
    use_azuread_auth = true
  }
}

provider "azurerm" {
  resource_provider_registrations = "none"
  storage_use_azuread             = true
  features {}
}