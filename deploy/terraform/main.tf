# ShadowGate Terraform Module
# Deploys ShadowGate on AWS EC2

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

variable "name" {
  description = "Name prefix for resources"
  type        = string
  default     = "shadowgate"
}

variable "vpc_id" {
  description = "VPC ID to deploy into"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the instance"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to SSH"
  type        = list(string)
  default     = []
}

variable "config_content" {
  description = "ShadowGate configuration YAML content"
  type        = string
}

# Security Group
resource "aws_security_group" "shadowgate" {
  name        = "${var.name}-sg"
  description = "Security group for ShadowGate"
  vpc_id      = var.vpc_id

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Admin API (restrict in production)
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  # SSH (if key provided)
  dynamic "ingress" {
    for_each = length(var.allowed_ssh_cidrs) > 0 ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_ssh_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name}-sg"
  }
}

# IAM Role for the instance
resource "aws_iam_role" "shadowgate" {
  name = "${var.name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_instance_profile" "shadowgate" {
  name = "${var.name}-profile"
  role = aws_iam_role.shadowgate.name
}

# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# EC2 Instance
resource "aws_instance" "shadowgate" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.shadowgate.id]
  iam_instance_profile   = aws_iam_instance_profile.shadowgate.name

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    # Install dependencies
    yum update -y
    yum install -y docker
    systemctl start docker
    systemctl enable docker

    # Create config directory
    mkdir -p /etc/shadowgate

    # Write configuration
    cat > /etc/shadowgate/config.yaml << 'CONFIGEOF'
    ${var.config_content}
    CONFIGEOF

    # Pull and run ShadowGate
    docker pull shadowgate:latest || echo "Using local image"

    docker run -d \
      --name shadowgate \
      --restart=always \
      -p 80:8080 \
      -p 443:8443 \
      -p 9090:9090 \
      -v /etc/shadowgate:/etc/shadowgate:ro \
      shadowgate:latest \
      -config /etc/shadowgate/config.yaml
  EOF
  )

  tags = {
    Name = var.name
  }
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.shadowgate.id
}

output "public_ip" {
  description = "Public IP address"
  value       = aws_instance.shadowgate.public_ip
}

output "private_ip" {
  description = "Private IP address"
  value       = aws_instance.shadowgate.private_ip
}
