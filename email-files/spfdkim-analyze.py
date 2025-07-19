import email
from email import policy
from email.parser import BytesParser

# === CONFIGURATION ===
eml_file_path = "P-Lab -3.2 you have a new statement2.eml" # Rename to your actual file, e.g., "phishing.eml"

# === PARSE THE EMAIL ===
with open(eml_file_path, 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

# === PRINT BASIC HEADERS ===
print("=== BASIC HEADERS ===")
print(f"From: {msg['From']}")
print(f"To: {msg['To']}")
print(f"Subject: {msg['Subject']}")
print(f"Date: {msg['Date']}")

# === EXTRACT AUTHENTICATION HEADERS ===
print("\n=== EMAIL AUTHENTICATION HEADERS ===")

# SPF result (typically comes from mail server)
received_spf = msg.get('Received-SPF')
if received_spf:
    print(f"SPF Check: {received_spf}")
else:
    print("SPF Check: Not found")

# DKIM-Signature is present if DKIM was applied
dkim_sig = msg.get('DKIM-Signature')
if dkim_sig:
    print("DKIM-Signature: Present")
    print(f"Partial DKIM-Signature:\n{dkim_sig[:150]}...")  # Trimmed for readability
else:
    print("DKIM-Signature: Not found")

# Authentication-Results often include DMARC, DKIM, SPF status
auth_results = msg.get('Authentication-Results')
if auth_results:
    print(f"Authentication-Results:\n{auth_results}")
    # You can optionally parse SPF/DKIM/DMARC results from this header
else:
    print("Authentication-Results header: Not found")

# Return-Path (may be used to detect spoofing)
return_path = msg.get('Return-Path')
if return_path:
    print(f"Return-Path: {return_path}")
else:
    print("Return-Path: Not found")
