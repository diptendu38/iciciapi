import secrets
import string
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import oci

def generate_random(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(secrets.choice(characters) for _ in range(length))
    return random_key

def read_public_key_from_vault(key_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        key_content = client.get_secret_bundle(key_ocid).data.secret_bundle_content.content.encode('utf-8')
        public_key = RSA.import_key(key_content)
    except Exception as ex:
        print("ERROR: failed to retrieve the key from the vault", ex)
        raise
    return public_key

def encrypt_symm(key, init_vector, value):
    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    padded_data = pad(value.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    iv_and_ciphertext = init_vector + encrypted
    return base64.urlsafe_b64encode(iv_and_ciphertext).decode('utf-8')

def encrypt_asymmetric(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

def encryption_logic(payload, key_ocid):
    randomno = generate_random(16)
    init_vector = generate_random(16)
    public_key = read_public_key_from_vault(key_ocid)
    encryptedData = encrypt_symm(randomno.encode('utf-8'), init_vector.encode('utf-8'), payload)
    encryptedKey = encrypt_asymmetric(public_key, randomno)
    return encryptedData,encryptedKey

    #print("Random Number:", randomno)
    #print("EncryptedData:", encryptedData)
    #print("EncryptedKey:", encryptedKey)
