#!/usr/bin/env python3
import base64
import datetime as dt
import os
import textwrap
import xml.etree.ElementTree as ET

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


METADATA_URL = os.environ.get("METADATA_URL")
ELABFTW_HOST = os.environ.get("ELABFTW_HOST")
ELABFTW_API_KEY = os.environ.get("ELABFTW_API_KEY")
ELABFTW_IDP_ID = os.environ.get("ELABFTW_IDP_ID")
VERBOSE = os.environ.get("VERBOSE") or False
FORCE_PATCH = os.environ.get("FORCE_PATCH") or False
REQUIRED_SUBJECT_CN = os.environ.get("REQUIRED_SUBJECT_CN", "login.microsoftonline.us")


NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def fetch_metadata_xml(url: str, timeout=20) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def fetch_current_cert() -> str:
    url = f"{ELABFTW_HOST.rstrip('/')}/api/v2/idps/{ELABFTW_IDP_ID}"
    headers = {"Authorization": f"{ELABFTW_API_KEY}", "Accept": "application/json"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()["x509"].strip().replace("\n", "")


def subject_common_name(cert: x509.Certificate) -> str:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return ""


def cert_validity_window(cert):
    """
    Return (nb, na) as timezone-aware UTC datetimes using cryptography's UTC properties.
    """
    return cert.not_valid_before_utc, cert.not_valid_after_utc


def iter_signing_cert_b64(xml_text: str):
    """
    Yields Base64-encoded DER bodies of signing X509 certificates found in metadata.
    Looks under any KeyDescriptor with use='signing' or without the attribute.
    """
    root = ET.fromstring(xml_text)

    # Look across common SAML locations for KeyDescriptor entries
    key_paths = [
        ".//md:IDPSSODescriptor/md:KeyDescriptor",
        ".//md:RoleDescriptor/md:KeyDescriptor",
        ".//md:SPSSODescriptor/md:KeyDescriptor",
        ".//md:KeyDescriptor",
    ]

    seen = set()
    for path in key_paths:
        for kd in root.findall(path, NS):
            use_attr = kd.get("use")
            if use_attr is not None and use_attr.lower() != "signing":
                continue  # only care about signing keys
            for cert in kd.findall(".//ds:X509Certificate", NS):
                b64 = "".join(cert.text.split())
                if b64 and b64 not in seen:
                    seen.add(b64)
                    yield b64


def b64_to_x509(b64_body: str) -> x509.Certificate:
    der = base64.b64decode(b64_body)
    return x509.load_der_x509_certificate(der, default_backend())


def to_pem(b64_body: str) -> str:
    return "".join(textwrap.wrap(b64_body, 64))


def choose_best_cert(candidates):
    """
    Policy: among currently valid certs, choose the one with the most recent NotBefore.
    Returns tuple (best_b64, cert_obj) or (None, None) if none valid.
    """
    now = dt.datetime.now(dt.timezone.utc)
    valid = []
    for b64 in candidates:
        try:
            c = b64_to_x509(b64)
            nb, na = cert_validity_window(c)
            cn = subject_common_name(c)
            if cn == REQUIRED_SUBJECT_CN and nb <= now <= na:
                valid.append((b64, c, nb))
        except Exception:
            continue

    if not valid:
        return None, None

    # Pick the cert with the most recent NotBefore
    valid.sort(key=lambda t: t[2], reverse=True)  # t[2] is nb
    return valid[0][0], valid[0][1]


def patch_elabftw(new_cert_pem: str):
    payload = {"x509": new_cert_pem, "x509_new": new_cert_pem}
    headers = {
        "Authorization": f"{ELABFTW_API_KEY}",
        "Content-Type": "application/json",
    }
    resp = requests.patch(
        f"{ELABFTW_HOST}/api/v2/idps/{ELABFTW_IDP_ID}",
        headers=headers,
        json=payload,
        timeout=30,
    )
    if resp.status_code == 200:
        print(f"New cert patched for {ELABFTW_HOST}")
    else:
        print(f"[ERROR] PATCH failed with {resp.status_code}: {resp.text}")


def say(msg: str):
    if VERBOSE:
        print(msg)


def main():
    say("[STEP] Fetching metadata XML")
    xml_text = fetch_metadata_xml(METADATA_URL)

    say("[STEP] Extracting signing certificates")
    certs = list(iter_signing_cert_b64(xml_text))
    if not certs:
        print("[ERROR] No signing certificates found in metadata.")
        return

    say(f"[INFO] Found {len(certs)} signing certs in metadata.")
    best_b64, best_cert = choose_best_cert(certs)
    if not best_b64:
        print("[ERROR] No currently valid signing certificate found.")
        return

    # Compare with current working cert
    current_norm = "".join(fetch_current_cert().split())
    best_norm = "".join(best_b64.split())

    if best_norm == current_norm:
        say("[OK] Current cert is already the newest valid signing cert. No action.")
        return

    now = dt.datetime.now(dt.timezone.utc)
    nb_best, na_best = cert_validity_window(best_cert)
    say(
        f"[INFO] New cert NotBefore: {nb_best.isoformat()}  NotAfter: {na_best.isoformat()}"
    )

    try:
        current_obj = b64_to_x509(current_norm)
        nb_cur, na_cur = cert_validity_window(current_obj)
        still_valid = nb_cur <= now <= na_cur
    except Exception:
        still_valid = False

    say("[INFO] Newer valid signing cert detected in metadata.")
    say(f"[INFO] Current cert still valid: {still_valid}")

    new_pem = to_pem(best_b64)
    if not still_valid or FORCE_PATCH:
        say("[STEP] Patching eLabFTW with the new cert")
        patch_elabftw(new_pem)


if __name__ == "__main__":
    main()
