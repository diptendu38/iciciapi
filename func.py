import json,secrets,string,oci,base64,logging,io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from fdk import response

PUBLIC_KEY = r"C:\Users\Diptendu Mukherjee\Desktop\Raychem\Server_Key\Public.pem"
KEYSTORE_FILE = r"C:\Users\Diptendu Mukherjee\Desktop\Raychem\Server_Key\Private.pem"


def create_json_payload(resquest_signature_encrypted_value, symmetric_key_encrypted_value):
    payload = {
        "encryptedData": resquest_signature_encrypted_value,
        "encryptedKey": symmetric_key_encrypted_value
    }
    return payload

def read_public_key_from_oci_vault(secret_ocid):
    config = oci.config.from_file()
    vault_client = oci.secrets.SecretsClient(config=config)

    response = vault_client.get_secret_version(secret_ocid, version_number=1)
    public_key_data = base64.b64decode(response.data.secret_bundle_content.content)
    public_key_str = public_key_data.decode('utf-8')

    return public_key_str


def generate_random(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(secrets.choice(characters) for _ in range(length))
    return random_key

def encrypt_symm(key, init_vector, value):
    backend = default_backend()
    key = key.encode('utf-8').ljust(32, b'\0')[:32]  
    iv = init_vector.encode('utf-8')
    data = value.encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    result = iv + encrypted_data

    return base64.b64encode(result).decode('utf-8')


def decrypt_symm(key, encrypted_str):
    encrypted = base64.b64decode(encrypted_str.encode('utf-8'))
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    key = key.encode('utf-8').ljust(32, b'\0')[:32]  # Convert to bytes and then pad
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode('utf-8')


def encrypt_asymm(b64_msg, file_path):
    public_key = RSA.import_key(read_public_key_from_oci_vault(file_path))
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_msg = cipher.encrypt(b64_msg)
    return base64.b64encode(encrypted_msg).decode('utf-8')

def decrypt_asymm(b64_encrypted_msg, file_path):
    with open(file_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_msg = cipher.decrypt(base64.b64decode(b64_encrypted_msg)).decode('utf-8')
    return base64.b64decode(decrypted_msg).decode('utf-8')

def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("function start")

    public_key_ocid = private_key_ocid = ""

    try:
        body = json.loads(data.getvalue())
        logging.getLogger().info("Request Body " + str(body))
        cfg = dict(ctx.Config())

        public_key_ocid = cfg["public_key_ocid"]
        logging.getLogger().info("Server Public Key OCID = " + public_key_ocid)
        private_key_ocid = cfg["server_private_key_ocid"]
        logging.getLogger().info("Server Private Key OCID = " + private_key_ocid)

    except Exception as e:
        print('ERROR: Missing configuration keys, client_private_key_ocid  client_public_key_ocid and server_public_key_ocid', e, flush=True)
        raise

    status_value = body["Type"]
    payload = body['Payload']
    json_response = {}


    if status_value == '1':
        session_key = generate_random(16)
        iv = generate_random(16)

        encrypted_data = encrypt_symm(session_key, iv, json.dumps(payload))
        print(f"EncryptedPayload :: {encrypted_data}")
        encrypted_key = encrypt_asymm(base64.b64encode(session_key.encode('utf-8')), public_key_ocid)
        print(f"EncryptedKey :: {encrypted_key}")

        #decrypted_payload = decrypt_symm(session_key, encrypted_data)
        #print(f"DecryptedPayload :: {decrypted_payload}")
        #plain_key = decrypt_asymm(encrypted_key, KEYSTORE_FILE)
        #print(f"DecryptedSessionKey :: {plain_key}")
        json_response = create_json_payload(
                encrypted_data,
                encrypted_key
            )
    
    else :
        print("Returning status 500")
        json_response = {"error": "Status 500 - Internal Server Error"}



    logging.getLogger().info("function end")
    logging.getLogger().info("Response Payload %s" , json_response)

    return response.Response(
        ctx, 
        response_data=json.dumps(json_response, ensure_ascii=False, indent=2),
        headers={"Content-Type": "application/json"}
    )

