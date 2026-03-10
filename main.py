from fastapi import FastAPI, Request
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

load_dotenv()
app = FastAPI()

# Global config para sa Private Key para hindi paulit-ulit binubuksan ang file (Performance Boost)
PRIVATE_KEY_PATH = "private_key.pem"

def decrypt_data(encrypted_b64):
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError("Private key file is missing on the server.")
        
    with open(PRIVATE_KEY_PATH, "rb") as k:
        # TAMA: load_pem_private_key ang kailangan natin para mag-decrypt
        # At ang keyword ay 'password', hindi 'password' sa public key
        private_key = serialization.load_pem_private_key(
            k.read(), 
            password=None  # Okay lang ang password=None dito dahil wala tayong passphrase
        )
        
    ciphertext = base64.b64decode(encrypted_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def get_db_connection():
    # Nagdagdag ng sslmode=require dahil kailangan ito ni Render para sa secure DB connections
    db_url = os.getenv("DATABASE_URL")
    if "sslmode" not in db_url:
        # Check kung kailangan i-append ang sslmode
        db_url += "?sslmode=require" if "?" not in db_url else "&sslmode=require"
        
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor)

@app.post("/ivrs/interface/panver")
async def verify_pan(request: dict):
    # Initialize connection objects
    conn = None
    cur = None
    
    try:
        trace_id = request.get("userreferencenumber", "UNKNOWN-TRACE")
        paramenc = request.get("paramenc", {})
        payload = paramenc.get("payload", {})
        
        # 1. Security Check (Genesys-Ready Auth)
        client_user = payload.get("username", "GUEST")
        encrypted_pass = payload.get("password")
        
        try:
            decrypted_pass = decrypt_data(encrypted_pass)
            if client_user != "EPLDT" or decrypted_pass != "SuperSecretPass123":
                return {"errcode": "401", "respdesc": "Unauthorized Access"}
        except Exception as decrypt_err:
            return {"errcode": "401", "respdesc": f"Auth Decryption Failed: {str(decrypt_err)}"}

        # 2. PAN Decryption
        encrypted_pan = payload.get("pan")
        real_pan = decrypt_data(encrypted_pan)
        
        # 3. Database Lookup
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT * FROM cardholders WHERE pan = %s", (real_pan,))
        db_result = cur.fetchone()

        # 4. Audit Logging
        status = "SUCCESS" if db_result else "NOT_FOUND"
        customer_name = db_result['customer_name'] if db_result else "NONE"
        
        cur.execute(
            "INSERT INTO api_audit_logs (trace_id, client_name, status, customer_found) VALUES (%s, %s, %s, %s)",
            (trace_id, client_user, status, customer_name)
        )
        conn.commit()

        if not db_result:
            return {"errcode": "01", "respdesc": "Card Not Found", "userreferencenumber": trace_id}

        # 5. Genesys-Compatible Response (Flattened)
        return {
            "errcode": "00",
            "respdesc": "Success",
            "userreferencenumber": trace_id,
            "customer_name": db_result['customer_name'],
            "flag_principal": str(db_result['is_principal']).lower(),
            "bc_card": db_result['bc_card']
        }

    except Exception as e:
        print(f"Server Error: {str(e)}")
        return {"errcode": "99", "respdesc": f"System Error: {str(e)}"}
        
    finally:
        # Mas safe na closure ng connection
        if cur: cur.close()
        if conn: conn.close()