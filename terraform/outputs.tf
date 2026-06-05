output "elastic_ip" {
  description = "Public Elastic IP — point your DNS A record here."
  value       = aws_eip.apigenie.public_ip
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.apigenie.id
}

output "ssh_command" {
  description = "SSH command to connect to the instance (uses your ssh_public_key_path counterpart private key)."
  value       = "ssh -i ${replace(var.ssh_public_key_path, ".pub", "")} ec2-user@${aws_eip.apigenie.public_ip}"
}

output "public_dns" {
  description = "AWS-assigned public DNS (use the Elastic IP and your own domain in production)."
  value       = aws_instance.apigenie.public_dns
}

output "ssm_command" {
  description = "Connect via SSM Session Manager — no SSH key, no open port 22 needed."
  value       = "aws ssm start-session --target ${aws_instance.apigenie.id} --region ${var.region}"
}

output "dns_hint" {
  description = "DNS A record you should create for the domain you intend to serve."
  value = var.domain != "" ? format(
    "Create an A record:  %s.  →  %s",
    var.domain, aws_eip.apigenie.public_ip
  ) : "Set var.domain to also get the recommended DNS record line."
}

output "first_login_hint" {
  description = "What to do after the EC2 instance is up."
  value       = <<-EOT
    1) Point your DNS A record at ${aws_eip.apigenie.public_ip}.
    2) SSM in:  aws ssm start-session --target ${aws_instance.apigenie.id} --region ${var.region}
       or SSH: ssh -i <private-key> ec2-user@${aws_eip.apigenie.public_ip}
    3) On the instance:
         git clone <your-repo-url> apigenie && cd apigenie
         ./scripts/bootstrap.sh           # interactive — pick "letsencrypt" if your DNS is live
         docker compose up -d --build
    4) Open https://${var.domain != "" ? var.domain : aws_eip.apigenie.public_ip}/admin
       and sign in as the admin username/password you chose in bootstrap.sh.
    5) Run the User-Lab in docs/USER_GUIDE.md §0 to validate the multi-user
       RBAC stack end-to-end.
  EOT
}
