terraform {
  required_version = ">= 1.5.0"
  required_providers {
    external = {
      source  = "hashicorp/external"
      version = ">= 2.3.0"
    }
  }
}

variable "store_dir" {
  type        = string
  default     = ".mgtls-terraform"
  description = "Path to the mgtls cryptographic workspace store"
}

variable "service_domain" {
  type        = string
  default     = "api.prod.internal"
  description = "Primary DNS SAN for the issued mTLS leaf certificate"
}

data "external" "mgtls_bundle" {
  program = ["bash", "${path.module}/mgtls-external.sh"]

  query = {
    store_dir      = var.store_dir
    service_domain = var.service_domain
  }
}

output "ca_cert_path" {
  value       = data.external.mgtls_bundle.result["ca_cert_path"]
  description = "Path to the Root/Intermediate CA chain PEM"
}

output "server_fullchain_path" {
  value       = data.external.mgtls_bundle.result["server_fullchain_path"]
  description = "Path to the issued server fullchain.pem"
}

output "server_key_path" {
  value       = data.external.mgtls_bundle.result["server_key_path"]
  description = "Path to the 0600 server private key"
  sensitive   = true
}

output "ssh_user_ca_pub_path" {
  value       = data.external.mgtls_bundle.result["ssh_user_ca_pub_path"]
  description = "Path to the OpenSSH User CA public key"
}
