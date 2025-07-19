#script to find and dowwnload files
import os
import email
from email import policy
from email.parser import BytesParser

# 📂 Step 1: Give the name of your .eml file (it should be in the same folder)
eml_file = "P-Lab -3.2 you have a new statement2.eml"  # <-- change this to your actual file name

# 📁 Step 2: Create a folder to save any attachments
output_folder = "attachments"
os.makedirs(output_folder, exist_ok=True)  # This makes the folder if it doesn't exist

# 📥 Step 3: Open and read the .eml email file
with open(eml_file, 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

# 🕵️‍♀️ Step 4: Go through each part of the email to look for attachments
for part in msg.walk():
    content_disposition = part.get("Content-Disposition", "")

    # 📎 If it's an attachment...
    if "attachment" in content_disposition:
        file_data = part.get_payload(decode=True)  # Get the actual file data
        file_name = part.get_filename()  # Get the file name (like "invoice.pdf")

        # 💾 If we found a file name, save it to the folder
        if file_name:
            save_path = os.path.join(output_folder, file_name)
            with open(save_path, "wb") as output_file:
                output_file.write(file_data)
            print(f"[+] Saved attachment: {file_name}")
