import requests
import uuid
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# --- CONFIGURATION ---
# I-uncomment ang Render URL kapag tapos na ang deployment
URL = "http://127.0.0.1:8000/ivrs/interface/panver"
# URL = "https://your-api-name.onrender.com/ivrs/interface/panver"

TEST_PAN = "2026000005"
CLIENT_ID = "EPLDT"
CLIENT_PASS = "SuperSecretPass123"
# ---------------------

def encrypt_with_public_key(plaintext: str):
    """Encrypts data using the RSA Public Key for secure transport."""
    try:
        with open("public_key.pem", "rb") as k:
            public_key = serialization.load_pem_public_key(k.read())
        
        encrypted = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    except FileNotFoundError:
        print("Error: public_key.pem not found. Run keygen.py first.")
        return None

def run_test():
    # 1. Generate Unique Trace ID (Genesys Style)
    trace_id = f"GENESYS-{uuid.uuid4().hex[:12].upper()}"

    # 2. Encrypt sensitive fields
    encrypted_pan = encrypt_with_public_key(TEST_PAN)
    encrypted_pass = encrypt_with_public_key(CLIENT_PASS)

    if not encrypted_pan or not encrypted_pass:
        return

    # 3. Construct the Genesys-Ready JSON Request
    data = {
        "userreferencenumber": trace_id,
        "paramenc": {
            "header": {
                "typ": "JWT",
                "alg": "RS256"
            },
            "payload": {
                "pan": encrypted_pan,
                "username": CLIENT_ID,
                "password": encrypted_pass
            }
        }
    }

    # 4. Display the payload (for Postman reference)
    print("\n" + "="*40)
    print("   GENESYS-READY REQUEST PAYLOAD")
    print("="*40)
    print(json.dumps(data, indent=2))
    print("="*40)

    # 5. Send the Request
    print(f"\nSending request to: {URL}...")
    try:
        response = requests.post(URL, json=data, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Server Response: {json.dumps(response.json(), indent=2)}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Is uvicorn running?")
    except Exception as e:
        print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    run_test()