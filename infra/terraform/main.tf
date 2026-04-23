# VulnOps — AWS Infrastructure (Terraform)
# Deploys: ECS Fargate services, RDS PostgreSQL, ElastiCache Redis, ALB
#
# Usage:
#   terraform init
#   terraform plan -var="db_password=<strong_password>"
#   terraform apply

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ─── Variables ────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  default     = "production"
}

variable "db_password" {
  description = "RDS master password"
  sensitive   = true
}

variable "openai_api_key" {
  description = "OpenAI API key for AI scoring"
  sensitive   = true
  default     = ""
}

variable "ecr_repo_prefix" {
  description = "ECR repository prefix"
  default     = "vulnops"
}

# ─── Networking ───────────────────────────────────────────────────────────────

resource "aws_vpc" "vulnops" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "vulnops-${var.environment}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.vulnops.id
  cidr_block        = cidrsubnet("10.0.0.0/16", 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "vulnops-private-${count.index}" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.vulnops.id
  cidr_block              = cidrsubnet("10.0.0.0/16", 8, count.index + 10)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "vulnops-public-${count.index}" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vulnops.id
  tags   = { Name = "vulnops-igw" }
}

# ─── Security Groups ──────────────────────────────────────────────────────────

resource "aws_security_group" "ecs_tasks" {
  name   = "vulnops-ecs-tasks"
  vpc_id = aws_vpc.vulnops.id

  ingress {
    from_port   = 8000
    to_port     = 8003
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rds" {
  name   = "vulnops-rds"
  vpc_id = aws_vpc.vulnops.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }
}

resource "aws_security_group" "redis" {
  name   = "vulnops-redis"
  vpc_id = aws_vpc.vulnops.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }
}

# ─── RDS PostgreSQL ───────────────────────────────────────────────────────────

resource "aws_db_subnet_group" "vulnops" {
  name       = "vulnops-db-subnet"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "postgres" {
  identifier        = "vulnops-${var.environment}"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.small"
  allocated_storage = 50

  db_name  = "vulnops"
  username = "vulnops"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.vulnops.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  deletion_protection     = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "vulnops-final-snapshot"

  storage_encrypted = true

  tags = { Name = "vulnops-postgres", Environment = var.environment }
}

# ─── ElastiCache Redis ────────────────────────────────────────────────────────

resource "aws_elasticache_subnet_group" "vulnops" {
  name       = "vulnops-cache-subnet"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "vulnops-redis"
  description          = "VulnOps enrichment queue"

  node_type            = "cache.t3.micro"
  num_cache_clusters   = 2
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.vulnops.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = { Name = "vulnops-redis", Environment = var.environment }
}

# ─── ECS Cluster ──────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "vulnops" {
  name = "vulnops-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "vulnops-ecs-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ─── ECS Task Definitions ─────────────────────────────────────────────────────

locals {
  db_url    = "postgresql://vulnops:${var.db_password}@${aws_db_instance.postgres.endpoint}/vulnops"
  redis_url = "rediss://${aws_elasticache_replication_group.redis.primary_endpoint_address}:6379/0"
}

resource "aws_ecs_task_definition" "ingest" {
  family                   = "vulnops-ingest"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([{
    name  = "ingest"
    image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.ecr_repo_prefix}/ingest:latest"
    portMappings = [{ containerPort = 8000 }]
    environment = [
      { name = "REDIS_URL", value = local.redis_url },
      { name = "DATABASE_URL", value = local.db_url },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/vulnops/ingest"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

data "aws_caller_identity" "current" {}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.postgres.endpoint
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.vulnops.name
}
