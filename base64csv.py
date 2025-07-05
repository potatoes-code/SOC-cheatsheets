#There is a csv file with base64 encoding 
import csv #reading and writing csv files
import base64 # to decode any values that are base 64 encoded

input_path = "suspicious_activities.csv" #the file paths
output_path = "decoded_suspicious_activities.csv" #new csv decoded

try:
    with open(input_path, newline='') as infile, open(output_path, mode='w', newline='') as outfile: #the format of csv
        reader = csv.reader(infile) #infile opens for reading
        writer = csv.writer(outfile) #opening the file for writing

        for row in reader: # processing each row
            print("Original row:", row) #print original for reference
            decoded_row = [] #creates an empty list to store the decoded values
            for cell in row: #decoding each cell 
                try:
                    # Attempt base64 decode
                    decoded = base64.b64decode(cell).decode('utf-8') #decodes to a string format
                    decoded_row.append(decoded)
                except (base64.binascii.Error, UnicodeDecodeError):
                    # If decoding fails, keep the original
                    decoded_row.append(cell)
            print("Decoded row: ", decoded_row)

            # Write decoded row to new CSV
            writer.writerow(decoded_row)

    print(f"Decoded content written to '{output_path}'.")

except FileNotFoundError:
    print("MISSING THE FILE")
except PermissionError:
    print("No permissions to read or write the file")
