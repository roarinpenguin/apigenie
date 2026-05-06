variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Name tag applied to all resources"
  type        = string
  default     = "apigenie"
}

variable "instance_type" {
  description = "EC2 instance type (t3.large recommended: 2 vCPU, 8 GB — needed for Kafka + Zookeeper)"
  type        = string
  default     = "t3.large"
}

variable "key_name" {
  description = "Name of the existing EC2 key pair for SSH access"
  type        = string
  default     = "roarinkey"
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to reach port 22. Restrict to your IP for security."
  type        = list(string)
  default     = ["87.121.148.232/32"]  # your IP only
}
