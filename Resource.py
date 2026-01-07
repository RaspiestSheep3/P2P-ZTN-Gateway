#Imports
import os
import json
import socket
import base64
import logging
import sqlite3
import colorlog
import threading
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constants
INCOMING_CONNECTION_HOST = "0.0.0.0"
INCOMING_CONNECTION_PORT = 12345
RESOURCE_LABEL = "Resource1"
CERT_PATH = "ResourceManagementResource1Certificate.json"
MASTER_PUBLIC_KEY_PEM = "MasterECCPublicKey.pem"
SESSION_TOKEN_EXPIRY_TIME = timedelta(minutes=30)

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
with open(f"ResourceGeneral.log", "w") as f:
    f.write("") #Clearing file
generalLogHandler = logging.FileHandler(f"ResourceGeneral.log")
generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
generalLogHandler.setLevel(logging.DEBUG) 

#Error handler
with open(f"ResourceErrors.log", "w") as f:
    f.write("")
errorLogHandler = logging.FileHandler(f"ResourceErrors.log")
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
    with open("ResourceECCPrivateKey.pem", "wb") as f:
        f.write(pemPrivate)
        
    pemPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("ResourceECCPublicKey.pem", "wb") as f:
        f.write(pemPublic)
    
def Start():
    #Listening for information
    incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
    incomingConnectionSocket.listen(5)

    logger.info("WAITING FOR REQUESTS")
    while True:
        clientSocket, addr = incomingConnectionSocket.accept()
        threading.Thread(target=HandleClient, args=(clientSocket,)).start()

def HandleClient(clientSocket):
    receivedMessage = json.loads(clientSocket.recv(512).rstrip(b"\0").decode())
    privateEphemeralKey, publicEphemeralKey = CreateEphemeralECCKey()
    privateEphemeralKeyBytes = privateEphemeralKey.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    publicEphemeralKeyBytes = publicEphemeralKey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    ephemeralKeyData = json.dumps({"Type" : "Client-Resource Ephemeral Key Transmission Response", "publicEphemeralKey" : base64.b64encode(publicEphemeralKeyBytes).decode()})
    clientSocket.send(ephemeralKeyData.encode().ljust(512, b"\0"))

    #Creating the shared secret
    clientEphemeralPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), 
        base64.b64decode(receivedMessage["publicEphemeralKey"])
    )
    ephemeralSecret = privateEphemeralKey.exchange(ec.ECDH(), clientEphemeralPublicKey)

    #Deriving an AES key
    clientAESKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Client-Resource Handshake",
    ).derive(ephemeralSecret)
    
    #Receiving the dummy attempt login
    aes = AESGCM(clientAESKey)
    
    #Receiving cert
    nonce = clientSocket.recv(12)
    clientCertInfoEncrypted = clientSocket.recv(2048).rstrip(b"\0")
    clientCertInfo = json.loads(aes.decrypt(nonce, clientCertInfoEncrypted, None).decode())
    
    #Signature test
    signature = clientCertInfo.pop("Signature")
    
    with open(MASTER_PUBLIC_KEY_PEM, "rb") as f:
        masterKey = serialization.load_pem_public_key(f.read())

    try:
        masterKey.verify(
            base64.b64decode(signature),
            json.dumps(clientCertInfo).encode(),
            ec.ECDSA(hashes.SHA256())   
        )
        logger.debug("Signature valid")
    except Exception as e:
        logger.error(f"Invalid signature : {e}")
        return

    #Sending our cert
    returnNonce = IncrementNonce(nonce, 1)
    
    with open(CERT_PATH, "r") as fileHandle:
        certInfo = json.loads(fileHandle.read())

    #Transmission of cert
    resourceCertInfoEncrypted = aes.encrypt(returnNonce, json.dumps(certInfo).encode(), None)
    
    clientSocket.send(resourceCertInfoEncrypted.ljust(2048, b"\0"))
    
    #Sending a session token 
    #My goal is to minimise the size of this for effiency 
    sessionToken = {
        "ID" : clientCertInfo["ID"],
        "Issuer" : certInfo["ID"],
        "Permissions" : clientCertInfo["Permissions"],
        "Expiry Time" : int((datetime.now(timezone.utc) + SESSION_TOKEN_EXPIRY_TIME).timestamp())
    }
    
    logger.debug(f"session token : {sessionToken}")

def CreateEphemeralECCKey():
    privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
    publicEphemeralKey = privateEphemeralKey.public_key()
    
    return privateEphemeralKey, publicEphemeralKey

def AssignFilesToSQL(acceptedLevels : list, filePath : str = None, folderPath : str = None):
    #This function can be called to bulk add files in a folder to the SQL   
    acceptedLevels = "|".join(acceptedLevels)
    
    conn = sqlite3.connect(f"{RESOURCE_LABEL}.db")
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS resourceFiles (
      fileLabel TEXT PRIMARY KEY,
      filePath TEXT NOT NULL UNIQUE,
      acceptedLevels TEXT NOT NULL  
    ) """)
    conn.commit()
    
    if(filePath):
        #Solo insert
        fileName = os.path.basename(filePath)
        cursor.execute("""
        INSERT INTO resourceFiles (
            fileLabel, filePath, acceptedLevels
        ) VALUES (?,?,?)
        """, (fileName, filePath, acceptedLevels))
        conn.commit()
    
    else:
        #Bulk insert
        rows = []
        
        filePaths = os.listdir(folderPath)
        for filePath in filePaths:
            fullPath = os.path.join(folderPath, filePath)
            if(os.path.isdir(fullPath)):
                AssignFilesToSQL(acceptedLevels.split("|"), None, fullPath)
            else:
                rows.append((filePath, fullPath,acceptedLevels))
        
        cursor.executemany("""
        INSERT INTO resourceFiles (
            fileLabel, filePath, acceptedLevels
        ) VALUES (?,?,?)
        """, rows)
        conn.commit()
    
    conn.close()

#AssignFilesToSQL(["Engineering LVL1, Engineering LVL2"], None, r"C:\Users\iniga\OneDrive\Programming\Testing")    
Start()
