provider "aws" {
  region = "us-east-1"
  # Hardcoded credentials — NUNCA faça isso
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_db_instance" "production" {
  identifier        = "prod-database"
  engine            = "postgres"
  engine_version    = "14"
  instance_class    = "db.t3.medium"
  allocated_storage = 100

  db_name  = "productiondb"
  username = "dbadmin"
  password = "SuperSecret123!"  # senha hardcoded

  publicly_accessible = true   # banco exposto publicamente
  skip_final_snapshot = true

  vpc_security_group_ids = [aws_security_group.db_sg.id]
}

resource "aws_security_group" "db_sg" {
  name = "prod-db-sg"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # aberto para o mundo
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
}

resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"  # bucket S3 público
}

resource "aws_lambda_function" "api" {
  filename      = "lambda.zip"
  function_name = "prod-api"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"

  environment {
    variables = {
      DB_PASSWORD     = "SuperSecret123!"
      STRIPE_KEY      = "my_stripe_secret_production_key"
      INTERNAL_IP     = "10.0.1.45"
      ADMIN_PANEL_URL = "https://admin.internal.company.com"
    }
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"          # permissão total — risco crítico
        Resource = "*"
      }
    ]
  })
}
