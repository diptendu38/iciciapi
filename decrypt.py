import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_v1_5
import oci,logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

'''def load_private_key_from_string(private_key_str):
    private_key = RSA.import_key(private_key_str)
    return private_key'''

'''def read_key_from_vault(key_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        key_content = client.get_secret_bundle(key_ocid).data.secret_bundle_content.content.encode('utf-8')
        key_bytes = base64.b64decode(key_content)
        return key_bytes
    except Exception as ex:
        logging.error("ERROR: failed to retrieve the key from the vault - {}".format(ex))
        raise'''
def fetch_private_key_from_vault(key_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        key_content = client.get_secret_bundle(key_ocid).data.secret_bundle_content.content
        key_bytes = base64.b64decode(key_content)
        private_key = RSA.import_key(key_bytes)
        return private_key
    except Exception as ex:
        print("ERROR: failed to retrieve the private key from the vault - {}".format(ex))
        raise

def decrypt_symmetric(plain_key, ciphertext):
    #key = plain_key.encode('utf-8')
    iv = ciphertext[:16]
    ciphertext_data = ciphertext[16:]

    cipher = AES.new(plain_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext_data), AES.block_size)
    return decrypted.decode('utf-8')

def decrypt_asymmetric(encrypted_data, private_key):
    cipher = PKCS1_v1_5.new(private_key)
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted_data = cipher.decrypt(encrypted_bytes, None)
    return decrypted_data.decode('utf-8')

'''def decryption_logic(encrypted_data, encrypted_key, key_ocid):
    private_key_bytes = read_key_from_vault(key_ocid)

    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    private_key = load_private_key_from_string(private_key_str)

    plain_key = decrypt_asymmetric(encrypted_key, private_key)
    print(f"Decrypted Session Key: {plain_key}")

    decrypted_payload = decrypt_symmetric(plain_key, encrypted_data)
    print(f"Decrypted Payload: {decrypted_payload}")
    return decrypted_payload'''

def decryption_logic(encrypted_data, encrypted_key, key_ocid):
    private_key = fetch_private_key_from_vault(key_ocid)
    plain_key = decrypt_asymmetric(encrypted_key, private_key)
    print(f"Decrypted Session Key: {plain_key}")
    decrypted_payload = decrypt_symmetric(plain_key, encrypted_data)
    print(f"Decrypted Payload: {decrypted_payload}")
    return decrypted_payload

