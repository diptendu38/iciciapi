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

def load_public_key_from_oci_vault(secret_ocid, compartment_id):
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    vault_client = oci.secrets.SecretsClient(config={}, signer=signer)

    response = vault_client.get_secret_bundle(secret_id=secret_ocid, compartment_id=compartment_id)
    secret_content = base64.b64decode(response.data.secret_bundle_content.content)

    return RSA.import_key(secret_content)

def encryption_logic(payload, cert_ocid):
    randomno = generate_random(16)
    init_vector = generate_random(16)
    iv_bytes = init_vector.encode('utf-8')
    compartment_id = 'ocid1.compartment.oc1..aaaaaaaatoj2hox2reiyvvlayuphc3i7pcssx7gvu3a6n4c6zutjcjrm6uiq'
    public_key = load_public_key_from_oci_vault(cert_ocid, compartment_id)
    encrypted_data = encrypt_symmetric(randomno, init_vector, payload)
    encrypted_key = encrypt_asymmetric(bank_public_key, randomno)
    
    return encrypted_data,encrypted_key,base64.b64encode(iv_bytes).decode('utf-8')
