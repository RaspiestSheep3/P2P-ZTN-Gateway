#Imports
import os
import json
import socket
import base64
import logging
import colorlog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constants
INCOMING_CONNECTION_HOST = "0.0.0.0"
INCOMING_CONNECTION_PORT = 12346
SERVER_CONNECTION_PORT = 12345
CERT_PATH = "UserJohnSmith1Certificate.json"
MASTER_PUBLIC_KEY_PEM = "MasterECCPublicKey.pem"

#Logging setup
logFormatter = colorlog.ColoredFormatter(
            "%(log_color)s%(levelname)s: %(message)s",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        )

consoleLogHandler = logging.StreamHandler()
consoleLogHandler.setFormatter(logFormatter)
consoleLogHandler.setLevel(logging.DEBUG)

# General handler
with open(f"ClientGeneral.log", "w") as f:
    f.write("") #Clearing file
generalLogHandler = logging.FileHandler(f"ClientGeneral.log")
generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
generalLogHandler.setLevel(logging.DEBUG) 

#Error handler
with open(f"ClientErrors.log", "w") as f:
    f.write("")
errorLogHandler = logging.FileHandler(f"ClientErrors.log")
errorLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
errorLogHandler.setLevel(logging.ERROR)  

#Creating logger
logger = logging.getLogger("colorLogger")
logger.setLevel(logging.DEBUG)

# Adding handlers to the logger
logger.addHandler(consoleLogHandler) 
logger.addHandler(generalLogHandler)    
logger.addHandler(errorLogHandler) 

def IncrementNonce(oldNonce : bytes, increment : int):
    try:
        oldNonceInt = int.from_bytes(oldNonce, byteorder="big")
        oldNonceInt = (oldNonceInt + increment) % (1 << 96) #Wraparound
        nonce = oldNonceInt.to_bytes(12, byteorder="big")
        return nonce
    except Exception as e:
        logger.error(f"Error {e} in IncrementNonce", exc_info=True)

#Keypair generation
def CreateECCKeypair():
    privateKey = ec.generate_private_key(ec.SECP256R1())
    publicKey = privateKey.public_key()

    pemPrivate = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  
    )
    with open("ClientECCPrivateKey.pem", "wb") as f:
        f.write(pemPrivate)
        
    pemPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("ClientECCPublicKey.pem", "wb") as f:
        f.write(pemPublic)
    return privateKey, publicKey

#Setting up a connection to the Resource

def ConnectToResource(privateEphemeralKey, publicEphemeralKeyBytes): 
    resourceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    resourceSocket.connect(("127.0.0.1", SERVER_CONNECTION_PORT))
    
    ephemeralKeyData = json.dumps({"Type" : "Client-Resource Ephemeral Key Transmission", "publicEphemeralKey" : base64.b64encode(publicEphemeralKeyBytes).decode()})
    resourceSocket.send(ephemeralKeyData.encode().ljust(512, b"\0"))
    receivedMessage = json.loads(resourceSocket.recv(512).rstrip(b"\0").decode())
    logger.debug(receivedMessage)

    #Creating the shared secret
    serverEphemeralPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), 
        base64.b64decode(receivedMessage["publicEphemeralKey"])
    )
    ephemeralSecret = privateEphemeralKey.exchange(ec.ECDH(), serverEphemeralPublicKey)

    #Deriving an AES key
    serverAESKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Client-Resource Handshake",
    ).derive(ephemeralSecret)

    aes = AESGCM(serverAESKey) 
    
    #Loading in the cert info 
    with open(CERT_PATH, "r") as fileHandle:
        certInfo = json.loads(fileHandle.read())

    #Transmission of cert
    nonce = os.urandom(12)
    clientCertInfoEncrypted = aes.encrypt(nonce, json.dumps(certInfo).encode(), None)
    
    resourceSocket.send(nonce)
    resourceSocket.send(clientCertInfoEncrypted.ljust(2048, b"\0"))
           
    #Receiving cert
    resourceCertInfoEncrypted = resourceSocket.recv(2048).rstrip(b"\0")
    resourceCertInfo = json.loads(aes.decrypt(IncrementNonce(nonce, 1), resourceCertInfoEncrypted, None).decode())
    
    #Signature test
    signature = resourceCertInfo.pop("Signature")
    
    with open(MASTER_PUBLIC_KEY_PEM, "rb") as f:
        masterKey = serialization.load_pem_public_key(f.read())

    try:
        masterKey.verify(
            base64.b64decode(signature),
            json.dumps(resourceCertInfo).encode(),
            ec.ECDSA(hashes.SHA256())   
        )
        logger.debug("Signature valid")
    except Exception as e:
        logger.error(f"Invalid signature : {e}")
        return
           
    return resourceSocket, aes

#Ephemeral Key Creation
def CreateEphemeralECCKeypair():
    privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
    publicEphemeralKey = privateEphemeralKey.public_key()
    
    privateEphemeralKeyBytes = privateEphemeralKey.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    
    publicEphemeralKeyBytes = publicEphemeralKey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return privateEphemeralKey, publicEphemeralKey, privateEphemeralKeyBytes, publicEphemeralKeyBytes

resourceSocket, aes, privateKey, publicKey = None, None, None, None

def Start():
    global resourceSocket, aes, privateKey, publicKey
    
    #ECC setup
    privateKey, publicKey = CreateECCKeypair()
    
    #Resrouce ephmeral pair
    privateEphemeralKey, _, _, publicEphemeralKeyBytes = CreateEphemeralECCKeypair()
    resourceSocket, aes = ConnectToResource(privateEphemeralKey, publicEphemeralKeyBytes)

    
Start()
