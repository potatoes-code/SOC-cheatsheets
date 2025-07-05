# Simple tool to extract headers and URLs from .eml phishing emails
# you need the .eml(email file) in the same folder
# run this script in the terminal python phishing_analyzer.py --file phish1.eml 

import re
import argparse
from email import policy
from email.parser import BytesParser

# Function which extract useful email headers like From, To, Subject
def extract_email_headers(msg):
    headers = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Date": msg.get("Date"),
        "Return-Path": msg.get("Return-Path")
    }
    return headers

# Function to extract URLs from the email body (plain text or HTML)
def extract_urls_from_email(msg):
    urls = set()  # Set ensures we don't get duplicate links

    # Handle multipart emails (most emails have both plain text and HTML)
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    body = part.get_payload(decode=True).decode(errors="ignore")
                    # Use regex to find all URLs
                    urls.update(re.findall(r'(https?://[\w\-./?=#&%]+)', body))
                except Exception:
                    continue
    else:
        # Single-part email (rare, but still needs checking)
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
            urls.update(re.findall(r'(https?://[\w\-./?=#&%]+)', body))
        except Exception:
            pass

    return list(urls)

# Main function to load the email file and display extracted info
def analyze_email(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    print("\n--- Email Headers ---")
    headers = extract_email_headers(msg)
    for key, value in headers.items():
        print(f"{key}: {value}")

    print("\n--- URLs Found ---")
    urls = extract_urls_from_email(msg)
    if urls:
        for url in urls:
            print(f"URL: {url}")
    else:
        print("No URLs found.")

# Command-line usage setup
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Analyze a phishing email and extract headers and URLs.")
    parser.add_argument("--file", required=True, help="Path to the .eml email file")
    args = parser.parse_args()
    analyze_email(args.file)

