# Prod: alert when someone changes the reports bucket's policy, encryption or public
# access settings outside Terraform. Relies on the account's CloudTrail management events.

data "aws_iam_policy_document" "alerts_key" {
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
  statement {
    sid       = "AllowEventBridgeToPublish"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_kms_key" "alerts" {
  count                   = var.enable_security_alerting ? 1 : 0
  description             = "${local.name} security alert topic encryption"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.alerts_key.json
}

resource "aws_sns_topic" "security_alerts" {
  count             = var.enable_security_alerting ? 1 : 0
  name              = "${local.name}-security-alerts"
  kms_master_key_id = aws_kms_key.alerts[0].arn
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  count     = var.enable_security_alerting && var.alert_email != null ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "bucket_tampering" {
  count       = var.enable_security_alerting ? 1 : 0
  name        = "${local.name}-bucket-tampering"
  description = "Security-relevant configuration changes on the reports bucket"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy", "DeleteBucketPolicy",
        "PutBucketEncryption", "DeleteBucketEncryption",
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
        "PutBucketReplication", "DeleteBucketReplication",
      ]
      requestParameters = { bucketName = [aws_s3_bucket.reports.id] }
    }
  })
}

resource "aws_cloudwatch_event_target" "bucket_tampering" {
  count = var.enable_security_alerting ? 1 : 0
  rule  = aws_cloudwatch_event_rule.bucket_tampering[0].name
  arn   = aws_sns_topic.security_alerts[0].arn
}

data "aws_iam_policy_document" "security_alerts_topic" {
  count = var.enable_security_alerting ? 1 : 0

  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts[0].arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.bucket_tampering[0].arn]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  count  = var.enable_security_alerting ? 1 : 0
  arn    = aws_sns_topic.security_alerts[0].arn
  policy = data.aws_iam_policy_document.security_alerts_topic[0].json
}
