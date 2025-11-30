import hashlib
import json

def get_hashes(file_name):
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(file_name, 'rb') as f:
        data = f.read()
        sha256.update(data)
        sha1.update(data)
        md5.update(data)

    return {
        'SHA-256': sha256.hexdigest(),
        'SHA-1': sha1.hexdigest(),
        'MD5': md5.hexdigest()
    }

def save_hashes(hashes, filename):
    with open(filename, 'w') as f:
        json.dump(hashes, f)

def load_hashes(filename):
    with open(filename, 'r') as f:
        return json.load(f)

original_file = 'original.txt'
hashes_file = 'hashes.json'

original_hashes = get_hashes(original_file)
save_hashes(original_hashes, hashes_file)
print("Original hashes saved.")

with open('tampered.txt', 'w') as f:
    f.write("This file has been tampered!")

tampered_hashes = get_hashes('tampered.txt')

stored_hashes = load_hashes(hashes_file)

print("\nChecking file integrity:")

for hash_type in ['SHA-256', 'SHA-1', 'MD5']:
    if stored_hashes[hash_type] == tampered_hashes[hash_type]:
        print(f"{hash_type}: PASS")
    else:
        print(f"{hash_type}: FAIL - WARNING: File has been tampered!")