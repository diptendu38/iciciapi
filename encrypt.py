import string
import base64
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from cryptography.hazmat.backends import default_backend
import secrets
import oci

def generate_random(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(secrets.choice(characters) for _ in range(length))
    return random_key

def encrypt_symmetric(key, init_vector, value):
    try:
        key_bytes = key.encode('utf-8')
        iv_bytes = init_vector.encode('utf-8')
        value_bytes = value.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded_data = pad(value_bytes, AES.block_size)

        encrypted_data = cipher.encrypt(padded_data)

        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as ex:
        print(ex)

    return None

def encrypt_asymmetric(public_key,message):
    cipher = PKCS1_v1_5.new(public_key)
    message_bytes = message.encode('utf-8')
    chunk_size = 245
    chunks = [message_bytes[i:i + chunk_size] for i in range(0, len(message_bytes), chunk_size)]

    encrypted_data = b""
    for chunk in chunks:
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_data += encrypted_chunk

    return base64.b64encode(encrypted_data).decode('utf-8')

'''def load_public_key_from_oci_vault(secret_ocid, compartment_id):
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    vault_client = oci.secrets.SecretsClient(config={}, signer=signer)

    response = vault_client.get_secret_bundle(secret_id=secret_ocid, compartment_id=compartment_id)
    secret_content = base64.b64decode(response.data.secret_bundle_content.content)

    return RSA.import_key(secret_content)'''


def log_public_key_content(public_key):
    # Convert the public key to a PEM format string
    pem_format = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Log the public key content
    print("Public Key Contents:")
    print(pem_format)
    
def fetch_public_key_from_vault(cert_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        cert_content = client.get_secret_bundle(cert_ocid).data.secret_bundle_content.content
        cert_bytes = base64.b64decode(cert_content)
        public_key = RSA.import_key(cert_bytes)
        log_public_key_content(public_key)
        return public_key
    except Exception as ex:
        print("ERROR: failed to retrieve the certificate from the vault - {}".format(ex))
        raise

def encryption_logic(payload, cert_ocid):
    randomno = generate_random(16)
    init_vector = generate_random(16)
    iv_bytes = init_vector.encode('utf-8')
    public_key = fetch_public_key_from_vault(cert_ocid)
    encrypted_data = encrypt_symmetric(randomno, init_vector, payload)
    encrypted_key = encrypt_asymmetric(bank_public_key, randomno)
    
    return encrypted_data,encrypted_key,base64.b64encode(iv_bytes).decode('utf-8')
