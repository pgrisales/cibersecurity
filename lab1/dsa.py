from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Create a new DSA key
key = DSA.generate(2048)
f = open("public_key.pem", "w")
f.write(key.publickey().export_key().decode("utf-8"))
f.close()

# Read message that will be sign
message = open("message.txt", "rb").read()

# Sign the message
hash_obj = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(hash_obj)

# Load the public key
f = open("public_key.pem", "r")
pub_key = DSA.import_key(f.read())
verifier = DSS.new(pub_key, 'fips-186-3')

print(f"hash message: {hash_obj.digest().hex()}")
print()
print(f"signature: {signature.hex()}")
print()

# Save Sign Message
f = open("sign_message", "w")
f.write(signature.hex())
f.close()

# Save Hash Message
f = open("hash_message", "w")
f.write(hash_obj.digest().hex())
f.close()

# Verify the authenticity of the message
try:
    verifier.verify(hash_obj, signature)
    print("The message is authentic.")
except ValueError:
    print("The message is not authentic.")
