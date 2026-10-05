# Baseline: created in every environment (dev, stage, prod).

resource "aws_s3_bucket" "reports" {
  #checkov:skip=CKV2_AWS_62:No consumer for object events; tamper alerting uses CloudTrail (security_alerting.tf)
  bucket = local.name
}

resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    object_ownership = "BucketOwnerEnforced" # disables ACLs
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      # null -> AWS-managed aws/s3 key (dev, cheaper); otherwise the dedicated CMK.
      kms_master_key_id = var.use_customer_managed_key ? aws_kms_key.reports[0].arn : null
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  count  = var.enable_versioning ? 1 : 0
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-reports"
    status = "Enabled"
    filter {}

    expiration {
      days = var.report_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    dynamic "noncurrent_version_expiration" {
      for_each = var.enable_versioning ? [1] : []
      content {
        noncurrent_days = var.noncurrent_version_retention_days
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.reports]
}

data "aws_iam_policy_document" "reports" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.reports.arn,
      "${aws_s3_bucket.reports.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = data.aws_iam_policy_document.reports.json

  depends_on = [aws_s3_bucket_public_access_block.reports]
}

# ---- customer-managed key (stage, prod) ---------------------------------------

# Key policies: "*" in a key policy means "this key". Access is delegated to IAM in
# this account only; the replication role gets kms:Decrypt through its IAM policy.
data "aws_iam_policy_document" "account_key_policy" {
  #checkov:skip=CKV_AWS_109:Key policy - resource "*" is the key itself
  #checkov:skip=CKV_AWS_111:Key policy - resource "*" is the key itself
  #checkov:skip=CKV_AWS_356:Key policy - resource "*" is the key itself
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "reports" {
  count                   = var.use_customer_managed_key ? 1 : 0
  description             = "${local.name} report encryption"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.account_key_policy.json
}

resource "aws_kms_alias" "reports" {
  count         = var.use_customer_managed_key ? 1 : 0
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.reports[0].key_id
}
