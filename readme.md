#!/usr/bin/env python3
"""
vmaas_extract.py - Python conversion of the VMaaS "PatchesByOwner" PowerShell script.

FLOW (same as the PowerShell version)
    1. Resolve credentials: --username/--password, else VMAAS_USERNAME / VMAAS_PASSWORD
       environment variables (Ansible), else interactive prompt.
    2. POST /token (OAuth2 password grant) -> bearer token.
    3. GET /products (paginated).
    4. Per product: GET /legacy/api/v2/onprem/{productId}/patchesbyownerid
                    GET /legacy/api/v2/onprem/{productId}/hostsummarybyownerid
    5. Per product: GET /products/{productId}/cloudAccounts
    6. Per cloud account: GET /legacy/api/v2/cloud/{accountId}/patches/   (findings nested per host)
                          GET /legacy/api/v1/cloud/{accountId}/host_summary_no_fim/
    7. Tag every record with Source* fields and export.

OUTPUT CONTRACT (unchanged for Ansible)
    Last lines: HOSTSUMMARY_CSV=<path> and EXPORT_PATH=<path>; exit code 1 if no patches exported.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --------------------------------------------------------------------------- config
BASE_URL = os.environ.get("VMAAS_BASE_URL", "https://vmaas.gso.prod.us.caas.oneadp.com")
PAGE_SIZE = 1000
TOKEN_SAFETY_MARGIN_SEC = 60          # refresh token this many seconds before expiry
DEFAULT_TOKEN_LIFETIME_SEC = 300      # used if /token does not return expires_in
REQUEST_TIMEOUT_SEC = 120

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "output"
LATEST_DIR = OUTPUT_DIR / "latest"
LOG_DIR = SCRIPT_DIR / "logs"

log = logging.getLogger("vmaas")


# --------------------------------------------------------------------------- logging
def setup_logging(run_stamp: str) -> Path:
    """Equivalent of Write-Log: writes to console and to a timestamped log file."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logfile = LOG_DIR / f"VMaaS_PatchesByOwner_log-{run_stamp}.log"
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    log.setLevel(logging.INFO)
    for handler in (logging.StreamHandler(sys.stderr), logging.FileHandler(logfile, encoding="utf-8")):
        handler.setFormatter(fmt)
        log.addHandler(handler)
    return logfile


# --------------------------------------------------------------------------- API client
class VmaasClient:
    """Wraps authentication, token caching, retries and pagination."""

    def __init__(self, base_url: str, username: str, password: str, page_size: int = PAGE_SIZE):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self._password = password
        self.page_size = page_size
        self._token: str | None = None
        self._token_expiry = 0.0

        self.session = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=2,                       # 2s, 4s, 8s, 16s, 32s
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            respect_retry_after_header=True,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    # ---- Get-AuthToken
    def authenticate(self) -> str:
        url = f"{self.base_url}/token"
        body = {
            "grant_type": "password",
            "username": self.username,
            "password": self._password,
            "scope": "",
        }
        try:
            resp = self.session.post(
                url,
                data=body,  # application/x-www-form-urlencoded
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=REQUEST_TIMEOUT_SEC,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.error("Failed to authenticate - %s", exc)
            raise
        payload = resp.json()
        self._token = payload["access_token"]
        lifetime = int(payload.get("expires_in") or DEFAULT_TOKEN_LIFETIME_SEC)
        self._token_expiry = time.time() + max(lifetime - TOKEN_SAFETY_MARGIN_SEC, 30)
        return self._token

    # ---- Get-AuthHeaders (with caching instead of re-auth on every page)
    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() >= self._token_expiry:
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def _get(self, url: str) -> Any:
        resp = self.session.get(url, headers=self._headers(), timeout=REQUEST_TIMEOUT_SEC)
        if resp.status_code == 401:                 # token revoked/expired early -> one re-auth
            self.authenticate()
            resp = self.session.get(url, headers=self._headers(), timeout=REQUEST_TIMEOUT_SEC)
        resp.raise_for_status()
        return resp.json()

    # ---- Get-AllPages
    def get_all_pages(self, url_base: str) -> list"""
        Generic paginated GET. Handles the same response shapes as the PowerShell version:
        { items: [...] } | { resources: [...] } | [ ... ], with total in
        total | totalCount | meta.pagination.total.
        """
        all_items: list[Any] = []
        page = 1
        total_pages = 1
        sep = "&" if "?" in url_base else "?"

        while page <= total_pages:
            url = f"{url_base}{sep}page={page}&size={self.page_size}"
            try:
                response = self._get(url)
            except requests.RequestException as exc:
                log.error("GET %s failed - %s", url, exc)
                break
            if response is None:
                break

            if isinstance(response, list):
                batch, total = response, None
            else:
                batch = response.get("items") or response.get("resources") or []
                total = response.get("total") or response.get("totalCount")
                if not total:
                    total = ((response.get("meta") or {}).get("pagination") or {}).get("total")

            all_items.extend(batch)
            if not total:
                total = len(all_items)
            total_pages = max(1, -(-int(total) // self.page_size))   # ceiling division

            log.info("  Page %s of %s retrieved (%s / %s items so far)",
                     page, total_pages, len(all_items), total)
            if not batch:                               # guard against endless loops
                break
            page += 1

        return all_items


# --------------------------------------------------------------------------- helpers
def first_present(obj: Any, *keys: str) -> Any:
    """Return the first non-empty value among keys (case-insensitive), mirroring the PS elseif chains."""
    if not isinstance(obj, dict):
        return None
    lowered = {k.lower(): v for k, v in obj.items()}
    for key in keys:
        val = obj.get(key, lowered.get(key.lower()))
        if val not in (None, ""):
            return val
    return None


def resolve_product(product: Any) -> tuple[Any, Any]:
    if isinstance(product, str):
        return product, None
    return first_present(product, "productId", "id", "ProductId"), first_present(product, "productName", "ProductName")


def resolve_cloud_account(account: Any) -> tuple[Any, Any]:
    if isinstance(account, str):
        return account, None
    acc_id = first_present(account, "accountId", "cloudAccountId", "id", "AccountId")
    acc_name = first_present(account, "accountName", "AccountName")
    return acc_id, acc_name


def tag(records: Iterable[dict], **tags: Any) -> list"""Equivalent of Add-Member -Force for the Source* traceability fields."""
    out = []
    for rec in records:
        row = dict(rec) if isinstance(rec, dict) else {"value": rec}
        row.update(tags)
        out.append(row)
    return out


def to_frame(records: list[dict], snapshot_date: str, run_id: str) -> pd.DataFrame:
    """
    Flatten nested dicts into dotted columns (fixes System.Object[] in Export-Csv),
    serialise lists as JSON text, union all columns (same as the PS column-union step),
    and add SnapshotDate / RunId.
    """
    if not records:
        return pd.DataFrame()
    df = pd.json_normalize(records, sep=".")
    for col in df.columns:
        if df[col].map(lambda v: isinstance(v, (list, dict))).any():
            df[col] = df[col].map(
                lambda v: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
            )
    df.insert(0, "SnapshotDate", snapshot_date)
    df.insert(1, "RunId", run_id)
    return df


def write_dataset(df: pd.DataFrame, name: str, run_stamp: str, parquet: bool) -> Path:
    """Write timestamped history file + fixed-name 'latest' file for Power BI."""
    history = OUTPUT_DIR / f"{name}_{run_stamp}.csv"
    latest = LATEST_DIR / f"{name}_latest.csv"
    df.to_csv(history, index=False, encoding="utf-8-sig")
    df.to_csv(latest, index=False, encoding="utf-8-sig")
    if parquet:
        df.astype("string").to_parquet(LATEST_DIR / f"{name}_latest.parquet", index=False)
        df.astype("string").to_parquet(OUTPUT_DIR / f"{name}_{run_stamp}.parquet", index=False)
    return history


def resolve_credentials(args: argparse.Namespace) -> tuple[str, str] | None:
    if args.username and args.password:
        return args.username, args.password
    user, pwd = os.environ.get("VMAAS_USERNAME"), os.environ.get("VMAAS_PASSWORD")
    if user and pwd:
        log.info("Using VMaaS credentials from environment for %s", user)
        os.environ.pop("VMAAS_PASSWORD", None)          # Remove-Item Env:VMAAS_PASSWORD
        return user, pwd
    if sys.stdin.isatty():
        log.info("Prompting for VMaaS credentials...")
        user = input("Enter your ADP username (UPN format, e.g. user@es.adp.adp.com): ").strip()
        pwd = getpass.getpass("SSO password for VMaaS: ")
        if user and pwd:
            return user, pwd
    return None


# --------------------------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser(description="Export VMaaS patches and host summaries for Power BI.")
    parser.add_argument("--username", help="ADP UPN username (optional; else env/prompt)")
    parser.add_argument("--password", help="Password (optional; prefer env var VMAAS_PASSWORD)")
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE)
    parser.add_argument("--parquet", action="store_true", help="Also write Parquet files")
    args = parser.parse_args()

    run_dt = datetime.now(timezone.utc)
    run_stamp = run_dt.strftime("%Y-%m-%d-%H-%M-%S")
    snapshot_date = run_dt.strftime("%Y-%m-%d")
    run_id = str(uuid.uuid4())

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    LATEST_DIR.mkdir(parents=True, exist_ok=True)
    setup_logging(run_stamp)
    log.info("Script started at: %s", run_dt.isoformat())

    creds = resolve_credentials(args)
    if not creds:
        log.error("No credentials provided. Exiting.")
        return 1

    client = VmaasClient(args.base_url, *creds, page_size=args.page_size)

    log.info("Authenticating to VMaaS...")
    client.authenticate()
    log.info("Authentication successful.")

    log.info("Retrieving list of accessible products...")
    products = client.get_all_pages(f"{client.base_url}/products")
    log.info("Found %s products.", len(products))
    if not products:
        log.error("No products found for this account. Exiting.")
        return 1

    all_patches: list[dict] = []
    all_host_summaries: list[dict] = []
    dim_products: list[dict] = []
    dim_cloud_accounts: list[dict] = []

    for product in products:
        product_id, product_name = resolve_product(product)
        if not product_id:
            log.warning("Could not determine productId from item: %s", json.dumps(product, default=str))
            continue
        dim_products.append({"ProductId": product_id, "ProductName": product_name})

        # --- On-prem patches
        log.info("Retrieving on-prem patches for productId: %s (%s)", product_id, product_name)
        patches = client.get_all_pages(
            f"{client.base_url}/legacy/api/v2/onprem/{product_id}/patchesbyownerid")
        log.info("  Retrieved %s on-prem patch records for productId %s", len(patches), product_id)
        all_patches.extend(tag(patches, SourceProductId=product_id,
                               SourceProductName=product_name, SourceType="OnPrem"))

        # --- On-prem host summary
        log.info("Retrieving on-prem host summary for productId: %s (%s)", product_id, product_name)
        host_summaries = client.get_all_pages(
            f"{client.base_url}/legacy/api/v2/onprem/{product_id}/hostsummarybyownerid")
        log.info("  Retrieved %s on-prem host summary records for productId %s",
                 len(host_summaries), product_id)
        all_host_summaries.extend(tag(host_summaries, SourceProductId=product_id,
                                      SourceProductName=product_name, SourceType="OnPrem"))

        # --- Cloud accounts linked to this product
        log.info("Retrieving cloud accounts for productId: %s (%s)", product_id, product_name)
        cloud_accounts = client.get_all_pages(f"{client.base_url}/products/{product_id}/cloudAccounts")
        log.info("  Found %s cloud accounts for productId %s", len(cloud_accounts), product_id)

        for account in cloud_accounts:
            acc_id, acc_name = resolve_cloud_account(account)
            if not acc_id:
                log.warning("Could not determine cloudAccountId from item: %s",
                            json.dumps(account, default=str))
                continue
            dim_cloud_accounts.append({"CloudAccountId": acc_id, "CloudAccountName": acc_name,
                                       "ProductId": product_id, "ProductName": product_name})

            log.info("  Retrieving cloud patches for cloudAccountId: %s (%s) (product: %s / %s)",
                     acc_id, acc_name, product_id, product_name)
            cloud_hosts = client.get_all_pages(f"{client.base_url}/legacy/api/v2/cloud/{acc_id}/patches/")
            log.info("    Retrieved %s host records for cloudAccountId %s", len(cloud_hosts), acc_id)

            cloud_hs = client.get_all_pages(
                f"{client.base_url}/legacy/api/v1/cloud/{acc_id}/host_summary_no_fim/")
            log.info("    Retrieved %s host summary records for cloudAccountId %s", len(cloud_hs), acc_id)
            all_host_summaries.extend(tag(cloud_hs, SourceProductId=product_id,
                                          SourceProductName=product_name,
                                          SourceCloudAccountId=acc_id,
                                          SourceCloudAccountName=acc_name, SourceType="Cloud"))

            # Each host carries a nested "findings" array with the individual patch records.
            for host in cloud_hosts:
                if not isinstance(host, dict):
                    continue
                host_name = first_present(host, "name", "hostname", "Name")
                findings = host.get("findings") or []
                all_patches.extend(tag(findings, SourceProductId=product_id,
                                       SourceProductName=product_name,
                                       SourceCloudAccountId=acc_id,
                                       SourceCloudAccountName=acc_name,
                                       SourceHostName=host_name, SourceType="Cloud"))

    log.info("Total patch records collected: %s", len(all_patches))
    log.info("Total host summary records collected: %s", len(all_host_summaries))

    # --- Dimension tables (always written)
    for name, rows, key in (("VMaaS_Products", dim_products, ["ProductId"]),
                            ("VMaaS_CloudAccounts", dim_cloud_accounts, ["CloudAccountId", "ProductId"])):
        if rows:
            df = pd.DataFrame(rows).drop_duplicates(subset=key)
            df.insert(0, "SnapshotDate", snapshot_date)
            write_dataset(df, name, run_stamp, args.parquet)

    # --- Host summary (written regardless of patch result - fixes PS early-exit gap)
    hs_path = None
    if all_host_summaries:
        hs_path = write_dataset(to_frame(all_host_summaries, snapshot_date, run_id),
                                "VMaaS_HostSummary_Dump", run_stamp, args.parquet)
        log.info("Host summary export complete: %s", hs_path)
    else:
        log.warning("No host summary records were retrieved; no host summary CSV was created.")

    # --- Patches
    export_path = None
    if all_patches:
        export_path = write_dataset(to_frame(all_patches, snapshot_date, run_id),
                                    "VMaaS_PatchesByOwner_Dump", run_stamp, args.parquet)
        log.info("Export complete: %s", export_path)
    else:
        log.error("No patch records were retrieved; no CSV was created.")

    log.info("Script finished at: %s", datetime.now(timezone.utc).isoformat())

    # Same stdout contract as the PowerShell script (consumed by Ansible)
    if hs_path:
        print(f"HOSTSUMMARY_CSV={hs_path}")
    if export_path:
        print(f"EXPORT_PATH={export_path}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
