#failedlogin csv file exported from windows evet viewer(security log)
#there are parameters included such as eventID, timegenerated, targetusername, 
#workstationname and ip address
#good for spotting brute--force attacks or unathorized access attempts
import csv  # This module helps us read CSV files

# This function reads the CSV file and looks for failed login events (Event ID 4625)
def find_failed_logins(csv_file):
    with open(csv_file, newline='') as file:
        reader = csv.DictReader(file)  # Reads the CSV file as a list of dictionaries
        failed_attempts = []  # This will store each failed login found

        for row in reader:
            # Event ID 4625 means a failed login in Windows Security logs
            if row.get("EventID") == "4625":
                failed_attempt = {
                    "Time": row.get("TimeGenerated"),
                    "Username": row.get("TargetUserName"),
                    "Workstation": row.get("WorkstationName"),
                    "IP Address": row.get("IpAddress")
                }
                failed_attempts.append(failed_attempt)

        return failed_attempts  # Return all the failed login events we found

# This part runs the script when you open it in the terminal
if __name__ == "__main__":
    # The name of the CSV file you want to check
    file_path = "security_log.csv"  # Make sure this file is in the same folder as the script

    # Run the function and print the results
    results = find_failed_logins(file_path)

    print("Failed Login Attempts Found:\n")
    for entry in results:
        print(entry)
