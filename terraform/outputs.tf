output "vpc_id" {
  value = aws_vpc.baseline.id
}

output "production_subnet_id" {
  value = aws_subnet.production.id
}

output "management_subnet_id" {
  value = aws_subnet.management.id
}

output "management_security_group_id" {
  value = aws_security_group.management.id
}
