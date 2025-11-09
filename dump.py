import os
import base64, sys, requests
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend

"""
This script will dump all certs with validity dates
"""

METADATA_URL = os.environ.get("METADATA_URL")
REQUIRED_SUBJECT_CN = os.environ.get(
    "REQUIRED_SUBJECT_CN", "accounts.accesscontrol.windows.net"
)

xml = requests.get(METADATA_URL, timeout=30).content
root = etree.fromstring(xml)
ns = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
b64s = [n.text.strip() for n in root.findall(".//ds:X509Certificate", ns) if n.text]
for b64 in b64s:
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(b64), default_backend())
        subj = cert.subject.rfc4514_string()
        if f"CN={REQUIRED_SUBJECT_CN}" in subj:
            print(
                "…" + b64[-12:],
                subj,
                cert.not_valid_before_utc,
                cert.not_valid_after_utc,
            )
    except Exception as e:
        pass
