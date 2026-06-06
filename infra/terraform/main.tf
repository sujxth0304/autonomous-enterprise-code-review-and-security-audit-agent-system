terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
  }
  backend "gcs" {
    bucket = "code-review-terraform-state"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ─── GKE Cluster ─────────────────────────────────────────────────────────────

resource "google_container_cluster" "primary" {
  name     = "${var.cluster_name}-${var.environment}"
  location = var.region

  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.subnet.name

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  ip_allocation_policy {
    cluster_ipv4_cidr_block  = "/16"
    services_ipv4_cidr_block = "/22"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  addons_config {
    horizontal_pod_autoscaling {
      disabled = false
    }
    http_load_balancing {
      disabled = false
    }
  }
}

resource "google_container_node_pool" "application_nodes" {
  name       = "application-pool"
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.node_count

  autoscaling {
    min_node_count = var.min_nodes
    max_node_count = var.max_nodes
  }

  node_config {
    machine_type = var.machine_type
    disk_size_gb = 100
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      environment = var.environment
      app         = "code-review-agent"
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# ─── CloudSQL PostgreSQL ──────────────────────────────────────────────────────

resource "google_sql_database_instance" "postgres" {
  name             = "code-review-postgres-${var.environment}"
  database_version = "POSTGRES_16"
  region           = var.region

  deletion_protection = var.environment == "production"

  settings {
    tier            = var.db_tier
    edition         = "ENTERPRISE"
    disk_size       = 50
    disk_type       = "PD_SSD"
    disk_autoresize = true

    database_flags {
      name  = "max_connections"
      value = "200"
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
      }
    }

    maintenance_window {
      day          = 7  # Sunday
      hour         = 3
      update_track = "stable"
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = false
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      require_ssl     = true
    }

    availability_type = var.environment == "production" ? "REGIONAL" : "ZONAL"
  }
}

resource "google_sql_database" "codereview" {
  name     = "codereview"
  instance = google_sql_database_instance.postgres.name
}

resource "google_sql_user" "app_user" {
  name     = "codereview"
  instance = google_sql_database_instance.postgres.name
  password = var.db_password
}

# ─── Redis Memorystore ────────────────────────────────────────────────────────

resource "google_redis_instance" "cache" {
  name               = "code-review-redis-${var.environment}"
  tier               = var.environment == "production" ? "STANDARD_HA" : "BASIC"
  memory_size_gb     = var.redis_memory_gb
  region             = var.region
  redis_version      = "REDIS_7_0"
  authorized_network = google_compute_network.vpc.id

  redis_configs = {
    maxmemory-policy = "allkeys-lru"
  }
}

# ─── GCS Buckets ─────────────────────────────────────────────────────────────

resource "google_storage_bucket" "artifacts" {
  name                        = "${var.project_id}-code-review-artifacts-${var.environment}"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }

  cors {
    origin          = ["*"]
    method          = ["GET"]
    response_header = ["Content-Type"]
    max_age_seconds = 3600
  }
}

# ─── VPC Network ─────────────────────────────────────────────────────────────

resource "google_compute_network" "vpc" {
  name                    = "code-review-vpc-${var.environment}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "code-review-subnet-${var.environment}"
  ip_cidr_range = "10.0.0.0/18"
  region        = var.region
  network       = google_compute_network.vpc.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "192.168.0.0/18"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "192.168.64.0/22"
  }
}

resource "google_compute_router" "router" {
  name    = "code-review-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "code-review-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
