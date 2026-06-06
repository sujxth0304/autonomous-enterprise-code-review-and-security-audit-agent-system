output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.primary.name
}

output "cluster_endpoint" {
  description = "GKE cluster endpoint"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "postgres_connection_name" {
  description = "CloudSQL connection name for Cloud SQL Proxy"
  value       = google_sql_database_instance.postgres.connection_name
}

output "postgres_private_ip" {
  description = "CloudSQL private IP"
  value       = google_sql_database_instance.postgres.private_ip_address
}

output "redis_host" {
  description = "Redis Memorystore host"
  value       = google_redis_instance.cache.host
}

output "redis_port" {
  description = "Redis Memorystore port"
  value       = google_redis_instance.cache.port
}

output "artifacts_bucket" {
  description = "GCS artifacts bucket name"
  value       = google_storage_bucket.artifacts.name
}

output "database_url" {
  description = "Application database URL (asyncpg)"
  value = "postgresql+asyncpg://codereview:${var.db_password}@${google_sql_database_instance.postgres.private_ip_address}:5432/codereview"
  sensitive = true
}

output "redis_url" {
  description = "Redis connection URL"
  value       = "redis://${google_redis_instance.cache.host}:${google_redis_instance.cache.port}/0"
}
