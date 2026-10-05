terraform {
  required_version = "~> 1.16"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project   = "ddos-eval"
      managedby = "terraform"
      component = "40-harness"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name_prefix" {
  type    = string
  default = "ddos-eval"
}

variable "instance_type" {
  description = <<-EOT
    t4g.micro: arm64, 2 vCPU, 1 GiB. Ample for an async client at the study's
    11 req/s ceiling.

    t4g.nano is cheaper ($0.0046/hour against roughly double for micro) but
    this account is on the AWS Free plan, which refuses any instance type that
    is not free-tier eligible:

      InvalidParameterCombination: The specified instance type is not
      eligible for Free Tier.

    t4g.micro is the smallest arm64 type on the eligible list for eu-west-1,
    and being free-tier eligible it draws on the monthly free allowance rather
    than the project budget. Constraint recorded 2026-09-30.
  EOT
  type        = string
  default     = "t4g.micro"
}

variable "use_elastic_ips" {
  description = <<-EOT
    Elastic IPs are OFF by default -- an amendment to decision D3, with reason.

    D3 required two distinct, stable source IPs because AWS WAF rate-based
    rules aggregate per source IP. Elastic IPs were the assumed mechanism.

    AWS now bills every public IPv4 address per hour, including an Elastic IP
    attached to a stopped instance. Since these hosts are stopped between run
    blocks for cost control, Elastic IPs would accrue charges through the idle
    majority of the study.

    The actual requirement is that the two hosts have DIFFERENT and KNOWN
    addresses during each run -- not identical addresses across the whole
    study. Auto-assigned public IPs satisfy that, provided the runner records
    both addresses in the run manifest and asserts they differ. It does.

    Set true if an unchanging address across all 60 runs becomes necessary.
  EOT
  type        = bool
  default     = false
}

variable "pinned_ami_id" {
  description = <<-EOT
    PIN THIS before the experiment runs.

    Discovered the hard way during the Week 5 pilot: with most_recent = true,
    AWS publishing a new Amazon Linux image causes the next `terraform apply`
    to REPLACE both instances. That destroyed a completed pilot run's records,
    and mid-experiment it would also have changed the operating system image
    between runs, quietly breaking comparability across the 60-run matrix.

    Empty string resolves the latest image, which is correct for first build.
    Once the experiment begins, set this to the resolved id so applies are
    non-destructive and every run executes on an identical image.

    Resolved id as at 2026-10-05: ami-043de3c7713de1480
  EOT
  type        = string
  default     = "ami-043de3c7713de1480"
}

# Used only when pinned_ami_id is empty, i.e. on a first build.
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-6.1-arm64"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# No inbound rules at all. Access is via SSM Session Manager, which works
# outbound-only, so neither host is reachable from the internet. That also
# keeps the study's own infrastructure off the attack surface it is measuring.
resource "aws_security_group" "gen" {
  name        = "${var.name_prefix}-generator"
  description = "Traffic generator hosts: egress only, no inbound"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to the endpoint under test, SSM, and package installs"
  }
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gen" {
  name               = "${var.name_prefix}-generator"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.gen.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "gen" {
  name = "${var.name_prefix}-generator"
  role = aws_iam_role.gen.name
}

locals {
  # Two roles, one template. They differ only in name and purpose -- identical
  # instance type, AMI, and network path, so neither host has a systematic
  # advantage that could bias a latency comparison between them.
  hosts = {
    attacker = "Generates the attacker profile in scenarios S2, S3 and S4"
    legit    = "Constant 1 req/s legitimate client in every scenario"
  }

  user_data = <<-EOF
    #!/bin/bash
    set -eux
    dnf -y update
    dnf -y install python3.12 python3.12-pip

    # chrony against the Amazon Time Sync Service is enabled by default on
    # AL2023. Clock offset between the two hosts is recorded per run so client
    # timestamps can be joined to CloudWatch's one-minute metric buckets.
    chronyc makestep || true

    python3.12 -m pip install --quiet aiohttp pyyaml
    mkdir -p /opt/ddos-eval
    chown ec2-user:ec2-user /opt/ddos-eval
  EOF
}

resource "aws_instance" "gen" {
  for_each = local.hosts

  ami                    = var.pinned_ami_id != "" ? var.pinned_ami_id : data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.gen.id]
  iam_instance_profile   = aws_iam_instance_profile.gen.name

  associate_public_ip_address = !var.use_elastic_ips
  user_data                   = local.user_data

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "${var.name_prefix}-gen-${each.key}"
    role = each.key
    note = each.value
  }
}

resource "aws_eip" "gen" {
  for_each = var.use_elastic_ips ? local.hosts : {}

  instance = aws_instance.gen[each.key].id
  domain   = "vpc"

  tags = {
    Name = "${var.name_prefix}-gen-${each.key}"
  }
}

output "attacker_instance_id" {
  value = aws_instance.gen["attacker"].id
}

output "legit_instance_id" {
  value = aws_instance.gen["legit"].id
}

output "attacker_public_ip" {
  description = "Recorded in every run manifest. The runner asserts this differs from the legitimate host's address."
  value       = var.use_elastic_ips ? aws_eip.gen["attacker"].public_ip : aws_instance.gen["attacker"].public_ip
}

output "legit_public_ip" {
  value = var.use_elastic_ips ? aws_eip.gen["legit"].public_ip : aws_instance.gen["legit"].public_ip
}

output "instance_type" {
  value = var.instance_type
}

output "ami_id" {
  description = "The image actually in use. Recorded per run so the environment is reproducible."
  value       = var.pinned_ami_id != "" ? var.pinned_ami_id : data.aws_ami.al2023.id
}

output "ami_pinned" {
  description = "False means a new AWS image release could replace the instances on the next apply."
  value       = var.pinned_ami_id != ""
}

# Instances hold irreplaceable run data between a run finishing and its upload.
# Refuse to destroy them by accident.
resource "null_resource" "replacement_guard" {
  triggers = {
    ami = var.pinned_ami_id != "" ? var.pinned_ami_id : data.aws_ami.al2023.id
  }
  lifecycle {
    create_before_destroy = true
  }
}

output "using_elastic_ips" {
  value = var.use_elastic_ips
}

# ---------------------------------------------------------------- results ---
# Run records are ~700 KB per run, well past the ~24 KB that SSM returns
# inline in a command result. Retrieval therefore goes via S3, which also
# gives the raw data durable storage independent of the instances -- the
# instances are stopped and could be rebuilt, the data cannot be regenerated.

resource "aws_s3_bucket" "results" {
  bucket        = "${var.name_prefix}-results-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# The generator hosts write their own run output and nothing else.
data "aws_iam_policy_document" "results_write" {
  statement {
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.results.arn, "${aws_s3_bucket.results.arn}/*"]
  }
}

resource "aws_iam_role_policy" "results_write" {
  name   = "${var.name_prefix}-results-write"
  role   = aws_iam_role.gen.id
  policy = data.aws_iam_policy_document.results_write.json
}

output "results_bucket" {
  description = "Where generator hosts upload run records, and where the orchestrator reads them from."
  value       = aws_s3_bucket.results.bucket
}
