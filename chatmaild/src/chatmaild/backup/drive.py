"""Drive v3, app-owned files only, with conservative resumable receipts."""

import hashlib
import re
from urllib.parse import urlparse

import requests

from . import FORMAT
from .model import ArchiveError, Receipt

API = "https://www.googleapis.com/drive/v3"
UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"
CHUNK = 256 * 1024
ID = re.compile(r"^[A-Za-z0-9_-]{1,200}$")


def file_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ArchiveError("invalid_drive_id")
    return value


class Drive:
    def __init__(self, token, *, session=None, checkpoint=lambda: None):
        self.token = token
        self.session = session or requests.Session()
        self.checkpoint = checkpoint
        self.on_commit = lambda: None

    def request(self, method, url, *, accepted=(200,), **kwargs):
        self.checkpoint()
        headers = {"Authorization": "Bearer " + self.token, **kwargs.pop("headers", {})}
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=(5, 30),
                allow_redirects=False,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise ArchiveError(
                "drive_transport", retryable=True, uncertain=method in ("POST", "PUT")
            ) from exc
        if response.status_code in accepted:
            return response
        status = response.status_code
        if status == 401:
            raise ArchiveError("reconnect")
        reason = "drive_http_" + str(status)
        if status == 403:
            try:
                upstream = response.json()["error"]["errors"][0]["reason"]
            except (ValueError, KeyError, IndexError, TypeError):
                upstream = "unknown"
            allowed = {
                "storageQuotaExceeded",
                "dailyLimitExceeded",
                "userRateLimitExceeded",
                "rateLimitExceeded",
                "insufficientFilePermissions",
                "appNotAuthorizedToFile",
            }
            reason = "drive_403_" + (upstream if upstream in allowed else "denied")
        retry = (
            status == 429
            or status >= 500
            or reason.endswith(("RateLimitExceeded", "rateLimitExceeded"))
        )
        raise ArchiveError(
            reason,
            retryable=retry,
            uncertain=status >= 500 and method in ("POST", "PUT"),
        )

    def principal(self):
        result = self.request(
            "GET", API + "/about", params={"fields": "user(permissionId)"}
        ).json()
        return file_id(result["user"]["permissionId"])

    def allocate(self):
        result = self.request(
            "GET",
            API + "/files/generateIds",
            params={"count": 1, "space": "drive", "type": "files"},
        ).json()
        return file_id(result["ids"][0])

    def folder(self):
        result = self.request(
            "POST",
            API + "/files",
            json={
                "name": "Chatmail encrypted archive",
                "mimeType": "application/vnd.google-apps.folder",
            },
            params={"fields": "id"},
        ).json()
        return file_id(result["id"])

    def metadata(self, object_id, *, missing=False):
        result = self.request(
            "GET",
            API + "/files/" + file_id(object_id),
            params={"fields": "id,size,md5Checksum,appProperties,trashed"},
            accepted=(200, 404) if missing else (200,),
        )
        return None if result.status_code == 404 else result.json()

    def verify(self, object_id, ciphertext):
        metadata = self.metadata(object_id)
        checksum = hashlib.sha256(ciphertext).hexdigest()
        if (
            metadata.get("trashed")
            or int(metadata.get("size", -1)) != len(ciphertext)
            or metadata.get("md5Checksum") != hashlib.md5(ciphertext).hexdigest()
            or metadata.get("appProperties", {}).get("sha256") != checksum
        ):
            raise ArchiveError("drive_checksum_mismatch")
        response = self.request(
            "GET",
            API + "/files/" + file_id(object_id),
            params={"alt": "media"},
            stream=True,
        )
        count, digest = 0, hashlib.sha256()
        try:
            for part in response.iter_content(CHUNK):
                self.checkpoint()
                count += len(part)
                if count > len(ciphertext):
                    raise ArchiveError("drive_checksum_mismatch")
                digest.update(part)
        finally:
            response.close()
        if count != len(ciphertext) or digest.hexdigest() != checksum:
            raise ArchiveError("drive_checksum_mismatch")
        return Receipt(object_id, count, checksum)

    def upload(self, object_id, folder_id, ciphertext, run_id):
        """Every retry uses the same preallocated ID; upload URI stays in RAM."""
        object_id, folder_id = file_id(object_id), file_id(folder_id)
        existing = self.metadata(object_id, missing=True)
        if existing:
            self.on_commit()
            return self.verify(object_id, ciphertext)
        metadata = {
            "id": object_id,
            "name": run_id + ".age",
            "parents": [folder_id],
            "appProperties": {
                "format": FORMAT,
                "run": run_id,
                "sha256": hashlib.sha256(ciphertext).hexdigest(),
            },
        }
        start = self.request(
            "POST",
            UPLOAD,
            params={"uploadType": "resumable"},
            json=metadata,
            headers={
                "X-Upload-Content-Type": "application/octet-stream",
                "X-Upload-Content-Length": str(len(ciphertext)),
            },
            accepted=(200, 201, 409),
        )
        if start.status_code == 409:
            self.on_commit()
            return self.reconcile_commit(object_id, ciphertext)
        uri = start.headers.get("Location", "")
        parsed = urlparse(uri)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "www.googleapis.com"
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
        ):
            raise ArchiveError("unsafe_upload_uri")
        offset, stalls = 0, 0
        while offset < len(ciphertext):
            end = min(offset + CHUNK, len(ciphertext))
            response = self.request(
                "PUT",
                uri,
                data=ciphertext[offset:end],
                headers={
                    "Content-Length": str(end - offset),
                    "Content-Range": f"bytes {offset}-{end - 1}/{len(ciphertext)}",
                },
                accepted=(200, 201, 308, 404, 410, 409),
            )
            if response.status_code in (404, 410):
                raise ArchiveError("upload_session_expired", retryable=True)
            if response.status_code == 409:
                self.on_commit()
                return self.reconcile_commit(object_id, ciphertext)
            if response.status_code in (200, 201):
                if end != len(ciphertext):
                    raise ArchiveError("upload_early_commit", uncertain=True)
                self.on_commit()
                break
            match = re.fullmatch(r"bytes=0-(\d+)", response.headers.get("Range", ""))
            acknowledged = int(match[1]) + 1 if match else 0
            if acknowledged < offset or acknowledged > end:
                raise ArchiveError("upload_range_mismatch", uncertain=True)
            stalls = stalls + 1 if acknowledged == offset else 0
            if stalls > 2:
                raise ArchiveError("upload_stalled", retryable=True)
            offset = acknowledged
        return self.verify(object_id, ciphertext)

    def reconcile_commit(self, object_id, ciphertext):
        try:
            return self.verify(object_id, ciphertext)
        except ArchiveError as exc:
            if exc.reason == "drive_http_404":
                raise ArchiveError(
                    "drive_commit_not_visible", retryable=True, uncertain=True
                ) from exc
            raise
