from unittest.mock import patch

from app.services.aws.s3_service import collect_s3_buckets


class RegionalS3Client:
    def list_buckets(self):
        return {"Buckets": [{"Name": "mumbai-bucket"}, {"Name": "london-bucket"}]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": "ap-south-1" if Bucket == "mumbai-bucket" else "eu-west-2"}

    def get_public_access_block(self, **_kwargs):
        return {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }}

    def get_bucket_policy(self, **_kwargs):
        raise Exception("NoSuchBucketPolicy")

    def get_bucket_encryption(self, **_kwargs):
        return {"ServerSideEncryptionConfiguration": {"Rules": []}}

    def get_bucket_versioning(self, **_kwargs):
        return {"Status": "Enabled"}

    def get_bucket_tagging(self, **_kwargs):
        raise Exception("NoSuchTagSet")


class RegionalS3Session:
    def client(self, *_args, **_kwargs):
        return RegionalS3Client()


def test_single_region_scan_excludes_buckets_from_other_regions():
    with patch("app.services.aws.region_cache.get_all_regions", return_value=["ap-south-1"]), \
         patch("app.services.aws.region_cache.get_resolved_scan_mode", return_value="single"), \
         patch("app.services.aws.s3_service.get_aws_session", return_value=RegionalS3Session()), \
         patch("app.services.aws.s3_service.get_account_id", return_value="123456789012"), \
         patch("app.services.aws.s3_service.get_boto_config", return_value=None):
        buckets = collect_s3_buckets()

    assert [bucket["name"] for bucket in buckets] == ["mumbai-bucket"]
    assert buckets[0]["region"] == "ap-south-1"
