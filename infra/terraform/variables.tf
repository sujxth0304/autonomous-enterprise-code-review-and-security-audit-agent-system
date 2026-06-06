variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment (development, staging, production)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "cluster_name" {
  description = "GKE cluster name prefix"
  type        = string
  default     = "code-review"
}

variable "machine_type" {
  description = "GKE node machine type"
  type        = string
  default     = "n2-standard-4"
}

variable "node_count" {
  description = "Initial node count per zone"
  type        = number
  default     = 2
}

variable "min_nodes" {
  description = "Minimum nodes for autoscaling"
  type        = number
  default     = 1
}

variable "max_nodes" {
  description = "Maximum nodes for autoscaling"
  type        = number
  default     = 10
}

variable "db_tier" {
  description = "CloudSQL instance tier"
  type        = string
  default     = "db-custom-4-16384"
}

variable "db_password" {
  description = "PostgreSQL application user password"
  type        = string
  sensitive   = true
}

variable "redis_memory_gb" {
  description = "Redis Memorystore memory in GB"
  type        = number
  default     = 5
}
