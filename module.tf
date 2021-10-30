provider "aws" {
  region = var.region
  profile = var.profile
}

locals {
  host_keys = yamldecode(data.aws_secretsmanager_secret_version.host_keys.secret_string)
  shared = yamldecode(data.aws_secretsmanager_secret_version.shared.secret_string)
}

data "aws_caller_identity" "current" {}
resource "aws_secretsmanager_secret" "host_keys" {
  name = "ssh-host-${var.cname}"
}
data "aws_secretsmanager_secret_version" "host_keys" {
  secret_id = aws_secretsmanager_secret.host_keys.id
}
resource "aws_secretsmanager_secret" "shared" {
  name = "shared-${var.cname}"
}
data "aws_secretsmanager_secret_version" "shared" {
  secret_id = aws_secretsmanager_secret.shared.id
}
data "template_file" "cloud_config" {
  template = file(var.cloud_config_path)
  vars = {
    deployment = var.deployment
    hostname = var.hostname
    domain = var.domain
    username = var.username
    region = var.region
    cname = var.cname
    admin_email = var.admin_email

    host_key_private = indent(8, local.host_keys.ed25519.private)
    host_key_public = indent(8, local.host_keys.ed25519.public)
    host_key_certificate = indent(8, local.host_keys.ed25519.certificate)

    redirect_url = var.redirect_url
    certify_script_url = var.certify_script_url

    substrate_release_url = var.substrate_release_url
    substrate_executable = var.substrate_executable
    substrate_chainspec_url = var.substrate_chainspec_url
    substrate_chain = var.substrate_chainspec_url != "" ? "/usr/share/${var.substrate_executable}/${var.substrate_executable}-chain-spec.json" : var.substrate_chain
    substrate_name = var.substrate_name
    substrate_port = var.substrate_port
    substrate_flags = join(" ", var.substrate_flags)
    substrate_args = join(" ", var.substrate_args)
    substrate_rpc_cors = var.substrate_rpc_cors
    substrate_ws_port = var.substrate_ws_port
    substrate_daemon_state = var.substrate_daemon_state
    alertmanager_port = var.alertmanager_port

    smtp_username = local.shared.smtp.username
    smtp_password = local.shared.smtp.password
    authorized_keys = indent(12, join("\n", [for authorized_key in var.authorized_keys : "- ${authorized_key}"])) # format hcl list as yml list
    bucket_name = (
      var.substrate_base_bucket.name != ""
        ? var.substrate_base_bucket.name
        : aws_s3_bucket.node.id
    )
  }
}
data "aws_ami" "ubuntu_latest" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  owners = ["099720109477"] # canonical
}

resource "aws_cloudwatch_log_group" "node" {
  name = "${var.cname}"
  retention_in_days = 30
}

resource "aws_instance" "node" {
  ami = data.aws_ami.ubuntu_latest.id
  instance_type = var.instance_type
  security_groups = [aws_security_group.node.name]
  associate_public_ip_address = true
  root_block_device {
    delete_on_termination = true
    volume_size = var.instance_root_volume_size
    volume_type = var.instance_root_volume_type
  }
  user_data = data.template_file.cloud_config.rendered
  iam_instance_profile = aws_iam_instance_profile.node.name
  tags = {
    Name = var.hostname
    Domain = var.domain
    cname = var.cname
    Source = var.tag_source
    Owner = var.admin_email
  }
}
data "aws_route53_zone" "node" {
  name = var.zone_lookup
}
resource "aws_route53_record" "node" {
  zone_id = data.aws_route53_zone.node.zone_id
  name = var.cname
  type = "A"
  ttl = var.ttl
  records = [aws_instance.node.public_ip]
}
#resource "aws_acm_certificate" "node" {
#  domain_name = var.cname
#  # we can only use acm certs (wih dns validation) for route53 managed domains
#  #subject_alternative_names = "${var.hostname}.${var.domain}"
#  validation_method = "DNS"
#  lifecycle {
#    create_before_destroy = true
#  }
#}
#resource "aws_route53_record" "node_validation" {
#  depends_on = [aws_acm_certificate.node]
#  name = element(tolist(aws_acm_certificate.node.domain_validation_options), 0)["resource_record_name"]
#  type = element(tolist(aws_acm_certificate.node.domain_validation_options), 0)["resource_record_type"]
#  zone_id = data.aws_route53_zone.node.zone_id
#  records = [element(tolist(aws_acm_certificate.node.domain_validation_options), 0)["resource_record_value"]]
#  ttl = 60
#}
#resource "aws_acm_certificate_validation" "node" {
#  certificate_arn = aws_acm_certificate.node.arn
#  validation_record_fqdns = aws_route53_record.node_validation.*.fqdn
#}

resource "aws_iam_role" "node" {
  name = "${var.deployment}-${var.hostname}"
  description = "parachain node role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com",
        }
      }
    ]
  })
}
resource "aws_iam_instance_profile" "node" {
  name = "${var.deployment}-${var.hostname}"
  role = aws_iam_role.node.name
}

resource "aws_iam_role_policy" "node" {
  name = "${var.deployment}-${var.hostname}"
  role = aws_iam_role.node.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "cloudwatch:PutMetricData",
          "ec2:DescribeVolumes*",
          "ec2:DescribeTags*",
          "logs:PutLogEvents*",
          "logs:DescribeLogStreams*",
          "logs:DescribeLogGroups*",
          "logs:CreateLogStream*",
          "logs:CreateLogGroup*",
        ]
        Effect = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "ssm:GetParameter",
        ]
        Effect = "Allow"
        Resource = "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
      },
      #{
      #  Action = [
      #    "s3:ListBucket",
      #    "s3:GetBucketLocation"
      #  ]
      #  Effect = "Allow"
      #  Resource = [
      #    aws_s3_bucket.node.arn,
      #  ]
      #},
      #{
      #  Action = [
      #    "s3:PutObject",
      #    "s3:PutObjectAcl",
      #    "s3:GetObject",
      #    "s3:GetObjectAcl",
      #    "s3:DeleteObject"
      #  ]
      #  Effect = "Allow"
      #  Resource = [
      #    aws_s3_bucket.node.arn,
      #    "${aws_s3_bucket.node.arn}/*",
      #  ]
      #},
      {
        Action = [
          "iam:GetServerCertificate",
        ]
        Effect = "Allow"
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:server-certificate/${var.cname}",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:server-certificate/${var.hostname}.${var.domain}",
        ]
      },
      {
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
        ]
        Effect = "Allow"
        Resource = [
          "arn:aws:secretsmanager:us-west-2:${data.aws_caller_identity.current.account_id}:secret:ssl-${var.hostname}.${var.domain}*",
          "arn:aws:secretsmanager:us-west-2:${data.aws_caller_identity.current.account_id}:secret:ssh-host-${var.cname}*",
          "arn:aws:secretsmanager:us-west-2:${data.aws_caller_identity.current.account_id}:secret:shared-${var.cname}*",
          "arn:aws:secretsmanager:us-west-2:${data.aws_caller_identity.current.account_id}:secret:substrate-${var.cname}*",
        ]
      },
    ]
  })
}

resource "aws_security_group" "node" {
  name = "${var.deployment}-${var.hostname}"
}
resource "aws_security_group_rule" "ssh" {
  security_group_id = aws_security_group.node.id
  type = "ingress"
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = (var.deployment_ip == "") ? var.trusted_cidr_blocks : concat(var.trusted_cidr_blocks, [ "${var.deployment_ip}/32" ])
}
resource "aws_security_group_rule" "http" {
  security_group_id = aws_security_group.node.id
  type = "ingress"
  from_port = 80
  to_port = 80
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  ipv6_cidr_blocks = ["::/0"]
}
resource "aws_security_group_rule" "https" {
  security_group_id = aws_security_group.node.id
  type = "ingress"
  from_port = 443
  to_port = 443
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  ipv6_cidr_blocks = ["::/0"]
}
resource "aws_security_group_rule" "p2p" {
  security_group_id = aws_security_group.node.id
  type = "ingress"
  from_port = var.substrate_port
  to_port = var.substrate_port
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  ipv6_cidr_blocks = ["::/0"]
}
resource "aws_security_group_rule" "all_egress" {
  security_group_id = aws_security_group.node.id
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  ipv6_cidr_blocks = ["::/0"]
}
resource "aws_security_group_rule" "grafana_alertmanager" {
  security_group_id = aws_security_group.node.id
  type = "ingress"
  from_port = var.alertmanager_port
  to_port = var.alertmanager_port
  protocol = "tcp"
  cidr_blocks = var.infra_cidr_blocks
}

resource "aws_ses_domain_identity" "node" {
  domain = aws_route53_record.node.name
}
resource "aws_ses_email_identity" "node_default_user" {
  email = "${var.username}@${aws_ses_domain_identity.node.domain}"
}
resource "aws_ses_domain_mail_from" "node" {
  domain = aws_ses_domain_identity.node.domain
  mail_from_domain = "bounce.${aws_ses_domain_identity.node.domain}"
}
resource "aws_route53_record" "node_mx" {
  zone_id = aws_route53_record.node.zone_id
  name = aws_ses_domain_mail_from.node.mail_from_domain
  type = "MX"
  ttl = "600"
  records = [
    "10 feedback-smtp.us-west-2.amazonses.com"
  ]
  depends_on = [
    aws_secretsmanager_secret.shared,
  ]
}
resource "aws_route53_record" "node_txt_spf" {
  zone_id = aws_route53_record.node.zone_id
  name = aws_ses_domain_mail_from.node.mail_from_domain
  type = "TXT"
  ttl = "600"
  records = [
    "v=spf1 include:amazonses.com -all"
  ]
}
resource "aws_route53_record" "node_txt_ses" {
  zone_id = aws_route53_record.node.zone_id
  name = "_amazonses.${aws_ses_domain_identity.node.id}"
  type = "TXT"
  ttl = "600"
  records = [
    aws_ses_domain_identity.node.verification_token
  ]
}
resource "aws_ses_domain_identity_verification" "node" {
  domain = aws_ses_domain_identity.node.id
  depends_on = [
    aws_route53_record.node_txt_ses,
    aws_secretsmanager_secret.shared,
  ]
}
resource "aws_s3_bucket" "node" {
  bucket = replace(var.cname, ".", "-")
  acl = "private"
  versioning {
    enabled = true
  }
  lifecycle_rule {
    prefix  = "var/lib/${var.substrate_executable}"
    enabled = true
    noncurrent_version_transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
    noncurrent_version_transition {
      days = 60
      storage_class = "GLACIER"
    }
    noncurrent_version_expiration {
      days = 90
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  tags = {
    Source = var.tag_source
    Owner = var.admin_email
  }
}
resource "aws_s3_bucket_public_access_block" "node" {
  bucket = aws_s3_bucket.node.id
  block_public_acls = true
  block_public_policy = true
}

resource "null_resource" "set_node_key" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      anytrue([ contains(var.substrate_flags, "--collator"), contains(var.substrate_flags, "--validator") ])
        ? "../../../module/substrate-node/insert-node-key.sh ${var.username} ${var.cname} ${var.substrate_executable} ${var.pass_base}"
        : "echo 'skipping node key injection. neither --collator nor --validator found in substrate_flags'"
    )
  }
}
resource "null_resource" "start_node_service" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      var.substrate_daemon_state != "enable --now"
        ? "ssh -o StrictHostKeyChecking=accept-new ${var.username}@${var.cname} 'sudo systemctl start ${var.substrate_executable}.service'"
        : "echo 'skipping node service start. node is configured to start automatically'"
    )
  }
}
resource "time_sleep" "await_node_service_start" {
  # todo: do an actual check for node running state
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  create_duration = var.substrate_daemon_state != "enable --now" ? "180s" : "0s"
}
resource "null_resource" "set_session_key_audi" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      anytrue([ contains(var.substrate_flags, "--collator"), contains(var.substrate_flags, "--validator") ])
        ? "../../../module/substrate-node/insert-session-key.sh ${var.username} ${var.cname} audi ${var.substrate_executable} ${var.pass_base}"
        : "echo 'skipping audi session key injection. neither --collator nor --validator found in substrate_flags'"
    )
  }
}
resource "null_resource" "set_session_key_babe" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      anytrue([ contains(var.substrate_flags, "--collator"), contains(var.substrate_flags, "--validator") ])
        ? "../../../module/substrate-node/insert-session-key.sh ${var.username} ${var.cname} babe ${var.substrate_executable} ${var.pass_base}"
        : "echo 'skipping babe session key injection. neither --collator nor --validator found in substrate_flags'"
    )
  }
}
resource "null_resource" "set_session_key_gran" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      anytrue([ contains(var.substrate_flags, "--collator"), contains(var.substrate_flags, "--validator") ])
        ? "../../../module/substrate-node/insert-session-key.sh ${var.username} ${var.cname} gran ${var.substrate_executable} ${var.pass_base}"
        : "echo 'skipping gran session key injection. neither --collator nor --validator found in substrate_flags'"
    )
  }
}
resource "null_resource" "set_session_key_imon" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      anytrue([ contains(var.substrate_flags, "--collator"), contains(var.substrate_flags, "--validator") ])
        ? "../../../module/substrate-node/insert-session-key.sh ${var.username} ${var.cname} imon ${var.substrate_executable} ${var.pass_base}"
        : "echo 'skipping imon session key injection. neither --collator nor --validator found in substrate_flags'"
    )
  }
}
resource "null_resource" "set_session_key_para" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      anytrue([ contains(var.substrate_flags, "--collator"), contains(var.substrate_flags, "--validator") ])
        ? "../../../module/substrate-node/insert-session-key.sh ${var.username} ${var.cname} para ${var.substrate_executable} ${var.pass_base}"
        : "echo 'skipping para session key injection. neither --collator nor --validator found in substrate_flags'"
    )
  }
}
resource "null_resource" "set_session_key_asgn" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = (
      anytrue([ contains(var.substrate_flags, "--collator"), contains(var.substrate_flags, "--validator") ])
        ? "../../../module/substrate-node/insert-session-key.sh ${var.username} ${var.cname} asgn ${var.substrate_executable} ${var.pass_base}"
        : "echo 'skipping asgn session key injection. neither --collator nor --validator found in substrate_flags'"
    )
  }
}
resource "time_sleep" "await_cert_availability" {
  # todo: do an actual check for cert existence
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  create_duration = var.substrate_daemon_state != "enable --now" ? "180s" : "0s"
}
resource "null_resource" "sync_ssl_cert" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
    time_sleep.await_cert_availability,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = "../../../module/substrate-node/sync-ssl-cert.sh ${var.cname}"
  }
}
resource "null_resource" "restart_node_service" {
  depends_on = [
    aws_route53_record.node,
    aws_instance.node,
    aws_security_group_rule.ssh,
    null_resource.set_node_key,
    null_resource.start_node_service,
    time_sleep.await_node_service_start,
    time_sleep.await_cert_availability,
    null_resource.sync_ssl_cert,
    null_resource.set_session_key_gran,
  ]
  triggers = {
    # change to node ip triggers re-provisioning
    node_ip = aws_instance.node.public_ip
  }
  provisioner "local-exec" {
    command = "ssh -o StrictHostKeyChecking=accept-new ${var.username}@${var.cname} 'sudo mv /var/log/${var.substrate_executable}/stderr.log /var/log/${var.substrate_executable}/stderr-$(date --utc --iso-8601=seconds).log && sudo systemctl restart ${var.substrate_executable}.service'"
  }
}
