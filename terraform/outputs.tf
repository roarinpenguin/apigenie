output "elastic_ip" {
  description = "Public Elastic IP — point your DNS A record here"
  value       = aws_eip.apigenie.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.apigenie.id
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i ~/.ssh/roarinkey.pem ec2-user@${aws_eip.apigenie.public_ip}"
}

output "public_dns" {
  description = "AWS-assigned public DNS (use Elastic IP for your domain instead)"
  value       = aws_instance.apigenie.public_dns
}

output "ssm_command" {
  description = "Connect via SSM Session Manager (no SSH key needed)"
  value       = "aws ssm start-session --target ${aws_instance.apigenie.id}"
}
