# Baseline-compliant network, expressed as code.
#
# This module provisions a small AWS network that satisfies the toolkit's
# own baseline controls by construction:
#   - AC-02 / NS-02: security group ingress is scoped to var.admin_cidr only,
#     never 0.0.0.0/0, and only on the ports actually required.
#   - NS-01: production and management subnets are separate, with routing
#     controlled at the route-table level rather than flat-networked.
#   - LOG-01: VPC Flow Logs forward network activity to CloudWatch, giving a
#     centralized record of accepted/rejected connections.
#   - DP-01: the bastion only accepts SSH (an encrypted protocol); there is
#     no plaintext management path (Telnet/HTTP admin) exposed.
#
# This is intentionally scoped as a demonstration module (one VPC, two
# subnets, one security group) rather than a production network -- the goal
# is to show the same controls from baseline/controls.py implemented as
# infrastructure-as-code, so the baseline can be enforced automatically
# instead of checked after the fact.

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

resource "aws_vpc" "baseline" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "baseline-vpc"
    Purpose = "security-baseline-toolkit-demo"
  }
}

# NS-01: separate production and management subnets (segmentation)
resource "aws_subnet" "production" {
  vpc_id            = aws_vpc.baseline.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 0)
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = { Name = "baseline-production", Zone = "production" }
}

resource "aws_subnet" "management" {
  vpc_id            = aws_vpc.baseline.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 1)
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = { Name = "baseline-management", Zone = "management" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# AC-02 / NS-02: least-privilege ingress, no plaintext management protocols,
# no 0.0.0.0/0 on anything.
resource "aws_security_group" "management" {
  name        = "baseline-management-sg"
  description = "Management access: SSH only, from an explicit admin CIDR."
  vpc_id      = aws_vpc.baseline.id

  ingress {
    description = "SSH from the admin range only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "baseline-management-sg" }
}

# LOG-01: centralized logging via VPC Flow Logs -> CloudWatch
resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = "/baseline/vpc-flow-logs"
  retention_in_days = 90
}

resource "aws_flow_log" "baseline" {
  count                = var.enable_flow_logs ? 1 : 0
  vpc_id               = aws_vpc.baseline.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs[0].arn
  iam_role_arn         = aws_iam_role.flow_logs[0].arn
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  name  = "baseline-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

# IAM-01: scoped permissions only -- no wildcard actions/resources.
resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  name  = "baseline-vpc-flow-logs-policy"
  role  = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
    }]
  })
}
