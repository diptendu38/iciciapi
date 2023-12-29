import json,logging,io
import encrypt

from fdk import response


def create_json_payload(resquest_signature_encrypted_value, symmetric_key_encrypted_value):
    payload = {
        "encryptedData": resquest_signature_encrypted_value,
        "encryptedKey": symmetric_key_encrypted_value
    }
    return payload



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
        encrypted_data,encrypted_key = encrypt.encryption_logic(json.dumps(payload),public_key_ocid) 
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

