import json
import logging
import io
import encrypt
import decrypt
from fdk import response

def create_json_payload(request_signature_encrypted_value, symmetric_key_encrypted_value, iv):
    payload = {
        "encryptedData": request_signature_encrypted_value,
        "encryptedKey": symmetric_key_encrypted_value,
        "iv": iv
    }
    return payload

def handle_encryption(payload, public_key_ocid):
    try:
        encrypted_data, encrypted_key, iv = encrypt.encryption_logic(json.dumps(payload),public_key_ocid)
        return create_json_payload(encrypted_data, encrypted_key, iv)
    except Exception as e:
        logging.exception("Encryption error: %s", e)
        return {"error": f"Encryption error: {e}"}

def handle_decryption(payload, private_key_ocid):
    try:
        if not payload:
            return {"error": "No JSON payload provided"}

        encrypted_key = payload.get("encryptedKey", "")
        encrypted_data = payload.get("encryptedData", "")

        return decrypt.decryption_logic(encrypted_data, encrypted_key, private_key_ocid)
    except Exception as e:
        logging.exception("Decryption error: %s", e)
        return {"error": f"Decryption error: {e}"}

def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("Function start")

    public_key_ocid = private_key_ocid = ""

    try:
        body = json.loads(data.getvalue())
        logging.getLogger().info("Request Body %s", body)
        cfg = dict(ctx.Config())

        public_key_ocid = cfg.get("public_key_ocid", "")
        logging.getLogger().info("Server Public Key OCID = %s", public_key_ocid)
        private_key_ocid = cfg.get("server_private_key_ocid", "")
        logging.getLogger().info("Server Private Key OCID = %s", private_key_ocid)

    except Exception as e:
        logging.exception('ERROR: Missing configuration keys, client_private_key_ocid, client_public_key_ocid, and server_public_key_ocid: %s', e)
        raise

    status_value = body.get("Type", "")
    payload = body.get("Payload", "")
    json_response = {}

    if status_value == '1':
        json_response = handle_encryption(payload, public_key_ocid)
    elif status_value == '2':
        json_response = handle_decryption(payload, private_key_ocid)
    else:
        logging.getLogger().info("Returning status 500")
        json_response = {"error": "Status 500 - Internal Server Error"}

    logging.getLogger().info("Function end")
    logging.getLogger().info("Response Payload: %s", json_response)

    return response.Response(
        ctx,
        response_data=json.dumps(json_response, ensure_ascii=False, indent=2),
        headers={"Content-Type": "application/json"}
    )
