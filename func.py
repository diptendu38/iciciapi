import json,secrets,string,oci,base64,logging,io
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

from fdk import response

PUBLIC_KEY = r"C:\Users\Diptendu Mukherjee\Desktop\Raychem\Server_Key\Public.pem"
KEYSTORE_FILE = r"C:\Users\Diptendu Mukherjee\Desktop\Raychem\Server_Key\Private.pem"


def create_json_payload(resquest_signature_encrypted_value, symmetric_key_encrypted_value):
    payload = {
        "encryptedData": resquest_signature_encrypted_value,
        "encryptedKey": symmetric_key_encrypted_value
    }
    return payload

def read_public_key_from_oci_vault(key_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        key_content = client.get_secret_bundle(key_ocid).data.secret_bundle_content.content.encode('utf-8')
        key_bytes = base64.b64decode(key_content)
        key_str = key_bytes.decode('utf-8')
    except Exception as ex:
        print("ERROR: failed to retrieve the key from the vault", ex)
        raise
    return key_str

def generate_random(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(secrets.choice(characters) for _ in range(length))
    return random_key

def encrypt_symm(key, init_vector, value):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, init_vector.encode('utf-8'))
    encrypted = cipher.encrypt(pad(value.encode('utf-8'), AES.block_size))
    return base64.b64encode(init_vector.encode('utf-8') + encrypted).decode('utf-8')


def decrypt_symm(key, encrypted_str):
    encrypted = base64.b64decode(encrypted_str.encode('utf-8'))
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')


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

