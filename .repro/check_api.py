#!/usr/bin/env python3
import urllib.request
import urllib.error
import json
import ssl

CM_HOST = "https://ec2-44-205-177-172.compute-1.amazonaws.com"
KEY_ID = "f11dd172f3ee4632ad55bb4834bcb95a4a73384647474fa3993bbab4862c7849"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Step 1: get token
auth_data = json.dumps({
    "grant_type": "password",
    "username": "admin",
    "password": "Koala2.20",
    "domain": "root",
    "auth_domain": "root"
}).encode()

req = urllib.request.Request(
    f"{CM_HOST}/api/v1/auth/tokens",
    data=auth_data,
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req, context=ctx) as resp:
    token_data = json.load(resp)
token = token_data["jwt"]
print(f"Token obtained: {token[:20]}...")

# Step 2: query the key
req2 = urllib.request.Request(
    f"{CM_HOST}/api/v1/vault/keys2/{KEY_ID}",
    headers={"Authorization": f"Bearer {token}"},
    method="GET"
)
with urllib.request.urlopen(req2, context=ctx) as resp:
    key_data = json.load(resp)

print("\n=== CM API Response for key ===")
print(f"id                : {key_data.get('id', '<NOT SET>')}")
print(f"name              : {key_data.get('name', '<NOT SET>')}")
print(f"state             : {key_data.get('state', '<NOT SET>')}")
print(f"revocationReason  : {key_data.get('revocationReason', '<NOT SET>')}")
print(f"revocationMessage : {key_data.get('revocationMessage', '<NOT SET>')}")

print("\n=== What Terraform config specified ===")
print("revocation_reason  = 'KeyCompromise'")
print("revocation_message = 'test-repro-message-TFIN-286'")

print("\n=== Analysis ===")
reason_in_cm = key_data.get('revocationReason', '<NOT SET>')
message_in_cm = key_data.get('revocationMessage', '<NOT SET>')

if reason_in_cm == "test-repro-message-TFIN-286" and message_in_cm == "KeyCompromise":
    print("BUG CONFIRMED: revocationReason and revocationMessage are SWAPPED in CM!")
    print(f"  CM revocationReason  = '{reason_in_cm}'  (should be 'KeyCompromise')")
    print(f"  CM revocationMessage = '{message_in_cm}'  (should be 'test-repro-message-TFIN-286')")
elif reason_in_cm == "KeyCompromise" and message_in_cm == "test-repro-message-TFIN-286":
    print("NO BUG: values are correctly stored.")
else:
    print(f"UNEXPECTED: reason={reason_in_cm!r}, message={message_in_cm!r}")
