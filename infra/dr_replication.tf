# Prod: cross-region replica of the reports bucket in var.dr_region.

resource "aws_kms_key" "replica" {
  count                   = var.enable_dr_replication ? 1 : 0
  provider                = aws.dr
  description             = "${local.name} DR replica encryption"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.account_key_policy.json
}

resource "aws_s3_bucket" "replica" {
  #checkov:skip=CKV_AWS_144:This is the DR replica; replicating it again adds nothing
  #checkov:skip=CKV_AWS_18:Access is logged on the primary bucket; replica only receives S3 replication writes
  #checkov:skip=CKV2_AWS_62:No consumer for object events on the replica
  count    = var.enable_dr_replication ? 1 : 0
  provider = aws.dr
  bucket   = "${local.name}-replica"
}

resource "aws_s3_bucket_ownership_controls" "replica" {
  count    = var.enable_dr_replication ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.replica[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "replica" {
  count                   = var.enable_dr_replication ? 1 : 0
  provider                = aws.dr
  bucket                  = aws_s3_bucket.replica[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica" {
  count    = var.enable_dr_replication ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.replica[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replica[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "replica" {
  count    = var.enable_dr_replication ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.replica[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "replica" {
  count    = var.enable_dr_replication ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.replica[0].id

  rule {
    id     = "expire-replicas"
    status = "Enabled"
    filter {}
    expiration {
      days = var.report_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.replica]
}

data "aws_iam_policy_document" "replication_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "replication" {
  count              = var.enable_dr_replication ? 1 : 0
  name               = "${local.name}-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json
}

data "aws_iam_policy_document" "replication" {
  count = var.enable_dr_replication ? 1 : 0

  statement {
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.reports.arn]
  }
  statement {
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
    ]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
  }
  statement {
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = ["${aws_s3_bucket.replica[0].arn}/*"]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.reports[0].arn]
  }
  statement {
    actions   = ["kms:Encrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.replica[0].arn]
  }
}

resource "aws_iam_role_policy" "replication" {
  count  = var.enable_dr_replication ? 1 : 0
  name   = "replicate-reports"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication[0].json
}

resource "aws_s3_bucket_replication_configuration" "reports" {
  count  = var.enable_dr_replication ? 1 : 0
  role   = aws_iam_role.replication[0].arn
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "dr"
    status = "Enabled"
    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.replica[0].arn
      storage_class = "STANDARD_IA"
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica[0].arn
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.reports, aws_s3_bucket_versioning.replica]
}
