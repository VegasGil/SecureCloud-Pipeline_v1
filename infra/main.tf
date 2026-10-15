provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "data" {
  bucket = "securecloud-pipeline-demo"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name = "open-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}