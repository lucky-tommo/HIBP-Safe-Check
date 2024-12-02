import hashlib
import requests
import urllib3
import csv
# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def create_sha1_hash(plaintext):
    """Create SHA-1 hash for the given plaintext."""
    hash_obj = hashlib.sha1(plaintext.encode('utf-8')).digest()
    return hash_obj.hex().upper()
def check_haveibeenpwned(full_hash):
    """Check if the SHA-1 hash has been pwned using the HIBP API."""
    prefix = full_hash[:5]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        # Disable SSL verification
        response = requests.get(url, verify=False)
        if response.status_code != 200:
            raise Exception(f"Error from API: {response.status_code}")
        # Store the response
        hashes = response.text.splitlines()
        # Compare each hash in the response to the full hash
        for line in hashes:
            hash_suffix, count = line.split(':')
            if prefix + hash_suffix == full_hash:
                return True  # Match found
        return False  # No match found
    except Exception as e:
        print(f"Error checking HIBP API: {e}")
        return None
def process_csv(file_path):
    """Process the CSV file, check each password, and write the results to a new file."""
    output_file = "HIBPchecked.csv"
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            # Ensure "password" column exists
            if "password" not in reader.fieldnames:
                print(f"Error: 'password' column not found in {file_path}.")
                return
            # Add "Compromised" column to the fieldnames
            fieldnames = reader.fieldnames + ["Compromised"]
            rows = []
            for row_num, row in enumerate(reader, start=1):
                plaintext = row["password"]
                if not plaintext:
                    print(f"Row {row_num}: Empty password. Skipping...")
                    row["Compromised"] = "No"
                    rows.append(row)
                    continue
                sha1_hash = create_sha1_hash(plaintext)
                print(f"Row {row_num}: Password: {plaintext}, SHA-1 Hash: {sha1_hash}")
                match = check_haveibeenpwned(sha1_hash)
                if match is None:
                    print(f"Row {row_num}: Error checking hash.")
                    row["Compromised"] = "No"  # Default to "No" in case of error
                elif match:
                    print(f"Row {row_num}: Password is compromised!")
                    row["Compromised"] = "Yes"
                else:
                    print(f"Row {row_num}: Password is not compromised.")
                    row["Compromised"] = "No"
                rows.append(row)
        # Write results to the output CSV
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Results saved to {output_file}")
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
    except Exception as e:
        print(f"An error occurred while processing the file: {e}")
def main():
    # Input CSV file path
    file_path = input("Enter the path to the CSV file: ")
    process_csv(file_path)
if __name__ == "__main__":
    main()