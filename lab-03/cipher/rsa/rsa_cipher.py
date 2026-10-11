import os
import rsa

# Thư mục keys nằm cạnh file này: cipher/rsa/keys
KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "publicKey.pem")
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "privateKey.pem")

os.makedirs(KEYS_DIR, exist_ok=True)


class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self):
        # Bước 1-4 của RSA: tạo cặp khóa (public key = (e, n), private key = (d, n))
        (public_key, private_key) = rsa.newkeys(1024)
        with open(PUBLIC_KEY_FILE, "wb") as p:
            p.write(public_key.save_pkcs1("PEM"))
        with open(PRIVATE_KEY_FILE, "wb") as p:
            p.write(private_key.save_pkcs1("PEM"))

    def load_keys(self):
        with open(PRIVATE_KEY_FILE, "rb") as p:
            private_key = rsa.PrivateKey.load_pkcs1(p.read())
        with open(PUBLIC_KEY_FILE, "rb") as p:
            public_key = rsa.PublicKey.load_pkcs1(p.read())
        return private_key, public_key

    def encrypt(self, message, key):
        # C = M^e mod n
        return rsa.encrypt(message.encode("utf-8"), key)

    def decrypt(self, ciphertext, key):
        # M = C^d mod n
        try:
            return rsa.decrypt(ciphertext, key).decode("utf-8")
        except Exception:
            return False

    def sign(self, message, key):
        return rsa.sign(message.encode("utf-8"), key, "SHA-1")

    def verify(self, message, signature, key):
        try:
            return rsa.verify(message.encode("utf-8"), signature, key) == "SHA-1"
        except Exception:
            return False
