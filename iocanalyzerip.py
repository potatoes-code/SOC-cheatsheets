#This is an indicator of compromise extractor for the IPs
#domains and hashes from a csvs file  
import csv #import the logs in a csv format.
import re

def extract_iocs_from_text(text):
    
    #Extract IP addresses and domain names from the input text using regex.
    #Returns sets of unique IPs and domains.
    
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
    return set(ips), set(domains)

def extract_iocs_from_csv(csv_file, columns):
    
    #Reads a CSV file and extracts IOCs from specified columns.
    #param csv_file: Path to CSV file.
    #param columns: List of column names to scan for IOCs.
    #return: Two sets - unique IP addresses and unique domains found.
    
    all_ips = set()
    all_domains = set()

    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            for col in columns:
                if col in row and row[col]:
                    ips, domains = extract_iocs_from_text(row[col])
                    all_ips.update(ips)
                    all_domains.update(domains)

    return all_ips, all_domains


if __name__ == "__main__":
    # Example: We want to scan and check 'Message' and 'Details' columns for IOCs
    #which is where suspicious data may hide 
    csv_path = "logs.csv"
    columns_to_scan = ['Message', 'Details']

    ips_found, domains_found = extract_iocs_from_csv(csv_path, columns_to_scan)

    print("IP Addresses found:")
    for ip in ips_found:
        print(ip)

    print("\nDomains found:")
    for domain in domains_found:
        print(domain)

#print and investigate further 