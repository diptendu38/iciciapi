import string
import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import secrets
import oci

def generate_random(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(secrets.choice(characters) for _ in range(length))
    return random_key

def encrypt_symmetric(key, init_vector, value):
    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    padded_data = pad(value.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    iv_and_ciphertext = init_vector + encrypted
    return base64.urlsafe_b64encode(iv_and_ciphertext).decode('utf-8')

def encrypt_asymmetric(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

def fetch_public_key_from_vault(cert_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        cert_content = client.get_secret_bundle(cert_ocid).data.secret_bundle_content.content
        public_key = RSA.import_key(cert_content)
        return public_key
    except Exception as ex:
        print("ERROR: failed to retrieve the certificate from the vault - {}".format(ex))
        raise
        
def encryption_logic(payload, key_ocid):
    randomno = generate_random(16)
    init_vector = generate_random(16)
    public_key = fetch_public_key_from_vault(key_ocid)
    '''public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')'''

    logging.info("Public key: {}".format(public_key_str))
    #public_key = load_private_key_from_string(public_key_str) 
    encrypted_data = encrypt_symm(randomno.encode('utf-8'), init_vector.encode('utf-8'), payload)
    encrypted_key = encrypt_asymmetric(public_key, randomno)
    
    return encrypted_data, encrypted_key
