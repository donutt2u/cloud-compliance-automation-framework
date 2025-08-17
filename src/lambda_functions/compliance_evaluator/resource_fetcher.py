"""
Fetches detailed configuration for AWS resources.
"""

import boto3
from typing import Dict, Any, Optional
from src.logger import get_logger

logger = get_logger(__name__)


def fetch_s3_bucket_details(bucket_name: str, region: str) -> Optional[Dict[str, Any]]:
    """
    Fetches the full configuration for a given S3 bucket.

    Args:
        bucket_name: The name of the S3 bucket.
        region: The AWS region of the bucket.

    Returns:
        A dictionary of the bucket's configuration attributes, or None on error.
    """
    try:
        # Note: S3 is a global service, but some calls are region-specific.
        # It's best practice to initialize the client in the target region.
        s3_client = boto3.client("s3", region_name=region)
        logger.info(f"Fetching details for S3 bucket: {bucket_name}")

        # Consolidate multiple API calls into one attribute dictionary
        attributes = {
            "BucketName": bucket_name,
            "Region": region,
            "PublicAccessBlockConfiguration": s3_client.get_public_access_block(
                Bucket=bucket_name
            ).get("PublicAccessBlockConfiguration", {}),
            "VersioningConfiguration": s3_client.get_bucket_versioning(
                Bucket=bucket_name
            ),
            "BucketEncryption": s3_client.get_bucket_encryption(Bucket=bucket_name),
        }

        # Remove keys that are not part of the config
        attributes["VersioningConfiguration"].pop("ResponseMetadata", None)

        return attributes

    except s3_client.exceptions.NoSuchBucket:
        logger.error(f"S3 bucket '{bucket_name}' not found.")
        return None
    except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        # This error means encryption is not configured, which is a compliance state.
        logger.warning(f"No server-side encryption found for bucket '{bucket_name}'.")
        attributes["BucketEncryption"] = {}
        return attributes
    except Exception as e:
        # Catch other potential boto3 errors (e.g., credentials, throttling)
        logger.error(
            f"Failed to fetch details for bucket '{bucket_name}': {e}", exc_info=True
        )
        return None


def get_resource_details(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Generic resource fetcher based on the event source and type.
    Currently supports S3 bucket creation events from CloudTrail via EventBridge.
    """
    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    if event_name == "CreateBucket":
        bucket_name = detail.get("requestParameters", {}).get("bucketName")
        region = detail.get("awsRegion")
        if bucket_name and region:
            return fetch_s3_bucket_details(bucket_name, region)

    logger.warning(f"Unsupported event type for resource fetching: {event_name}")
    return None
