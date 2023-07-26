from Crypto.Hash import SHA256
with open("secret_build_output.txt", 'r') as secrets_fp:
        secrets = secrets_fp.read()
secrets = secrets.split('\n\n')
aes_key = secrets[0]

rsa_public_key = secrets[2]
#print(rsa_public_key)

hash = SHA256.new()
firmware_and_message = "hlsdjkh" 
hash.update(firmware_and_message)
    # digest = hashes.Hash(hashes.SHA256())
    # digest.update(firmware_and_message)
firmware_hash = hash.hexdigest()
print(hash)
print ('\n' + firmware_hash)