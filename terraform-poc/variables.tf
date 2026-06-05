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
  description = "EC2 instance type. t3.large (2 vCPU / 8 GB) is the documented minimum — Kafka + Zookeeper are the limiting factors."
  type        = string
  default     = "t3.large"
}

variable "key_name" {
  description = "Logical name of the EC2 key pair resource created from var.ssh_public_key_path. Changing this forces re-creation of the key pair (but not the EC2 instance, because the instance references key_name as a string)."
  type        = string
  default     = "apigenie-key"
}

variable "ssh_public_key_path" {
  description = <<-EOT
    Path to your local SSH public key. Will be imported into AWS as the key pair
    used by the EC2 instance. The user_data script also adds ec2-user to the
    docker group so you don't need sudo for docker/docker-compose.

    Override in terraform.tfvars, e.g.:
      ssh_public_key_path = "~/.ssh/id_ed25519.pub"
  EOT
  type        = string
  default     = "~/.ssh/roarinkey.pub"
}

variable "ssh_allowed_cidrs" {
  description = <<-EOT
    CIDR blocks allowed to reach port 22 (SSH). The default is intentionally
    narrow — replace it with your own IP/CIDR. Discover yours with:
      curl -4s https://api.ipify.org
    Then in terraform.tfvars:
      ssh_allowed_cidrs = ["1.2.3.4/32"]

    The instance also supports SSM Session Manager (no public SSH needed) via
    the attached IAM instance profile — consider closing port 22 entirely once
    you have confirmed SSM works.
  EOT
  type        = list(string)
  default     = ["87.121.148.232/32"]
}

variable "domain" {
  description = <<-EOT
    Optional — the public DNS name you intend to point at the Elastic IP. Used
    only by the documentation output to print the recommended Let's Encrypt
    bootstrap command. Leave empty if you plan to keep self-signed certs.
  EOT
  type        = string
  default     = ""
}
