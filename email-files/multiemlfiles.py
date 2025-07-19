import email
from email import policy
from email.parser import BytesParser
import os

# === List of EML Files to Analyze ===
eml_files = [
    "P-Lab -3.2 you have a new statement2.eml",
    "P-Lab -3.2 you have a new statement.eml",
    "P-Lab -3.2 you have a new statement3.eml",
    "P-Lab -3.2 you have a new statement4.eml"
]

# === Function to Analyze Headers ===
def analyze_email_headers(eml_path):
    print(f"\n{'=' * 60}")
    print(f"📧 Analyzing: {eml_path}")
    print(f"{'=' * 60}")
    
    try:
        with open(eml_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        print(f"From: {msg['From']}")
        print(f"To: {msg['To']}")
        print(f"Subject: {msg['Subject']}")
        print(f"Date: {msg['Date']}")

        print("\n--- AUTHENTICATION HEADERS ---")

        received_spf = msg.get('Received-SPF')
        print(f"SPF Check: {received_spf if received_spf else 'Not found'}")

        dkim_sig = msg.get('DKIM-Signature')
        if dkim_sig:
            print("DKIM-Signature: Present")
            print(f"Partial DKIM: {dkim_sig[:100]}...")
        else:
            print("DKIM-Signature: Not found")

        auth_results = msg.get('Authentication-Results')
        print(f"Authentication-Results: {auth_results if auth_results else 'Not found'}")

        return_path = msg.get('Return-Path')
        print(f"Return-Path: {return_path if return_path else 'Not found'}")

    except Exception as e:
        print(f"Error processing {eml_path}: {e}")

# === Loop Over All EML Files ===
for eml_file in eml_files:
    analyze_email_headers(eml_file)
