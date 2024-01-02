import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import oci
import logging
from cryptography.hazmat.backends import default_backend
from cryptography import x509

def load_certificate_from_string(cert_str):
    cert_bytes = cert_str.encode('utf-8')
    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    return cert

def extract_public_key_from_certificate(cert):
    return cert.public_key()

def read_certificate_from_vault(cert_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        cert_content = client.get_secret_bundle(cert_ocid).data.secret_bundle_content.content.decode('utf-8')
        return cert_content
    except Exception as ex:
        logging.error("ERROR: failed to retrieve the certificate from the vault - {}".format(ex))
        raise

def decrypt_symmetric(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

def decrypt_asymmetric(b64_encrypted_msg, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_msg = cipher.decrypt(base64.b64decode(b64_encrypted_msg))
    return decrypted_msg

def decryption_logic(encrypted_data, encrypted_key, cert_ocid):
    cert_content = read_certificate_from_vault(cert_ocid)
    cert = load_certificate_from_string(cert_content)
    public_key = extract_public_key_from_certificate(cert)

    plain_key = decrypt_asymmetric(encrypted_key, public_key)
    print(f"Decrypted Session Key: {plain_key.decode('utf-8')}")

    iv_and_ciphertext = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    decrypted_payload = decrypt_symmetric(plain_key, iv, ciphertext)
    print(f"Decrypted Payload: {decrypted_payload}")
'''
# Example usage
encrypted_data = "b0NUU01yZ0I1c1dhUTlhenAPu-HcssSM8m6Ph1_Ok0vEnisudpHUTT4m49WvZQYxrvw1xjlUOrThsdTHyFcIxg=="
encrypted_key = "n07Ypu0+UFIFzwnL/PxA9Eu+oJ5j20AAuzQ5xLWMEGqDZwHEAFUejC7pQczLAYnp5M9DLAQ3s/fM34Kt/jwX0rFHLnEStNqtMQl7/NTv7mOzafKVb0/KYjGuJu6096OXhLHvjk/BDB1DzqqfCgaPndGCPh202aO2BKKon5WbZiQVrsaOIhJ9/SiRqETA48On/lk/NLpyvdZ/dqUsfwouB9Ni2JY9ouqPjIrynCip813rpIpRZnfnFiBP4/n7AICyIutBZKcds6dsXbxBZW4mqBWKldq2/omqxCbW6P8IqHwZ3atKLy9W8gfKhe1swFPClLJH8T9wjh/ThxLPNqJwaQ=="
cert_ocid = "your_certificate_ocid"

decryption_logic(encrypted_data, encrypted_key, cert_ocid)'''
