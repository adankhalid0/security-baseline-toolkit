variable "aws_region" {
  description = "AWS region to deploy the baseline network into."
  type        = string
  default     = "eu-north-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the baseline VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "admin_cidr" {
  description = <<-EOT
    CIDR block allowed to reach the management/SSH security group.
    Deliberately has no default -- the whole point of AC-02 (least-privilege
    ingress) is that this must be set explicitly to a known, narrow range
    (e.g. an office IP or VPN egress range), never 0.0.0.0/0.
  EOT
  type        = string
}

variable "enable_flow_logs" {
  description = "Whether to enable VPC Flow Logs (supports LOG-01: centralized logging)."
  type        = bool
  default     = true
}
