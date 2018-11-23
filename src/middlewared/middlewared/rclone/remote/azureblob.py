from middlewared.rclone.base import BaseRcloneRemote
from middlewared.schema import Str


class AzureBlobRcloneRemote(BaseRcloneRemote):
    name = "AZUREBLOB"
    title = "Microsoft Azure Blob Storage"

    buckets = True

    rclone_binary_path = "/usr/local/bin/rclone-1.42"
    rclone_type = "azureblob"

    credentials_schema = [
        Str("account", verbose="Account Name", required=True),
        Str("key", verbose="Account Key", required=True),
    ]
