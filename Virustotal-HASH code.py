import requests
import time

# For test use
API_KEYS = [
    'API1',
    'API2',
    'API3'
]

def check_hash_malicious(hash_value, api_key):
    # Query VirusTotal with the hash value
    url = 'https://www.virustotal.com/api/v3/files/' + hash_value
    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses

        result = response.json()
        if 'data' in result and 'attributes' in result['data']:
            attributes = result['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)

                if malicious > 0 or suspicious > 0:
                    return f"The hash value {hash_value} is potentially malicious."
                elif undetected > 0:
                    return f"The hash value {hash_value} has not been detected as malicious."
                else:
                    return f"The hash value {hash_value} has no available information."
            else:
                return f"No analysis stats available for the hash value {hash_value}."
        else:
            return f"No information available for the hash value {hash_value}."

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            if hash_value:
                return f"The hash value {hash_value} was not found on Virustotal."
            else:
                return f"Received 404 response from Virustotal, but hash value is empty."
        elif e.response.status_code == 401:
            if hash_value:
                return f"The hash value {hash_value} is not accessible. Recorded in 'Not found file hash.txt'."
            else:
                return f"Received 401 response from Virustotal, but hash value is empty."
        else:
            return f"Error: {e}"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Input scan hash file
input_file_path = 'INPUT FILE PATH'
# Output result file
output_file_path = 'OUTPUT FILE PATH'

with open(input_file_path, 'r', encoding="ISO-8859-1") as txtfile:
    lines = txtfile.readlines()

api_key_index = 0 

not_found_file_path = 'NOT FOUND FILE PATH'

with open(output_file_path, 'w', encoding='UTF-8') as outputfile, open(not_found_file_path, 'w', encoding='UTF-8') as not_found_file:
    for idx, line in enumerate(lines):
        hash_value = line.strip()
        api_key = API_KEYS[api_key_index]

        result = check_hash_malicious(hash_value, api_key)
        if "potentially" in result:
            outputfile.write(f"{hash_value}: {result}\n")
        elif "not found" in result.lower():
            not_found_file.write(f"{hash_value}\n")

        print(result)

        time.sleep(10)

        # Check if we have processed 498 hashes with the current API key
        if (idx + 1) % 498 == 0:
            api_key_index = (api_key_index + 1) % len(API_KEYS)  
            print(f'Switched to API key {api_key_index + 1}')
