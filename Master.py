import os
import json
import socket
import base64
import logging
import colorlog
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Global variables
privateKey, publicKey = None, None

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
with open(f"MasterGeneral.log", "w") as f:
    f.write("") #Clearing file
generalLogHandler = logging.FileHandler(f"MasterGeneral.log")
generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
generalLogHandler.setLevel(logging.DEBUG) 

#Error handler
with open(f"MasterErrors.log", "w") as f:
    f.write("")
errorLogHandler = logging.FileHandler(f"MasterErrors.log")
errorLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
errorLogHandler.setLevel(logging.ERROR)  

#Creating logger
logger = logging.getLogger("colorLogger")
logger.setLevel(logging.DEBUG)

# Adding handlers to the logger
logger.addHandler(consoleLogHandler) 
logger.addHandler(generalLogHandler)    
logger.addHandler(errorLogHandler) 

#Keypair generation
def CreateECCKeypair():
    privateKey = ec.generate_private_key(ec.SECP256R1())
    publicKey = privateKey.public_key()

    pemPrivate = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  
    )
    with open("MasterECCPrivateKey.pem", "wb") as f:
        f.write(pemPrivate)
        
    pemPublic = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("MasterECCPublicKey.pem", "wb") as f:
        f.write(pemPublic)
    return privateKey, publicKey

def CreateUserCertificate(name : str, ID : str, title : str, publicKeyBytesB64 : str, permissions : list, expiryDate : str, loginDays : dict, startTime : str, endTime : str, algorithmUsed : str, issuerID : str, issueDate : str, serial : int, version : int):
    permissionsDict = dict()
    
    for permission in permissions:
        permissionsDict[permission[0]] = permission[1]
    
    userDict = {
        "Name" : name,
        "ID" : ID,
        "Title" : title,
        "Public Key" : publicKeyBytesB64,
        "Permissions" : permissionsDict,
        "Expiry Date" : expiryDate,
        "Login Days" : {
            "Mon" : loginDays["Mon"],
            "Tue" : loginDays["Tue"],
            "Wed" : loginDays["Wed"],
            "Thu" : loginDays["Thu"],
            "Fri" : loginDays["Fri"],
            "Sat" : loginDays["Sat"],
            "Sun" : loginDays["Sun"]
        },
        "Start Time" : startTime,
        "End Time" : endTime,
        "Algorithm Used" : algorithmUsed,
        "Issuer" : issuerID,
        "Issue Date" : issueDate,
        "Serial" : serial,
        "Certifiate Version" : version
    }
    
    #Signing the user
    signatureBytes = privateKey.sign(
        json.dumps(userDict).encode(),
        ec.ECDSA(hashes.SHA256())
    )
    
    userDict["Signature"] = base64.b64encode(signatureBytes).decode()
    with open(f"User{secure_filename(ID)}Certificate.json", "w") as f:
        json.dump(userDict, f, indent=4)

def CreateResourceCertificate(name : str, ID : str, publicKeyBytesB64 : str, algorithmUsed : str, issuerID : str, issueDate : str, expiryDate : str, serial : int, version : int, ):
    resourceDict = {
        "Name" : name,
        "ID" : ID,
        "Public Key" : publicKeyBytesB64,
        "Algorithm Used" : algorithmUsed,
        "Issuer" : issuerID,
        "Issue Date" : issueDate,
        "Expiry" : expiryDate,
        "Serial" : serial,
        "Certifiate Version" : version,
    }
    
    signatureBytes = privateKey.sign(
        json.dumps(resourceDict).encode(),
        ec.ECDSA(hashes.SHA256())
    )
    
    resourceDict["Signature"] = base64.b64encode(signatureBytes).decode()
    with open(f"Resource{secure_filename(ID)}Certificate.json", "w") as f:
        json.dump(resourceDict, f, indent=4)

#!TEMP - for testing - in practice the keypair should never be created more than once because this means all previous certs are invalid
if(not os.path.exists("MasterECCPrivateKey.pem")):
   privateKey, publicKey = CreateECCKeypair() 
else:
    with open("MasterECCPrivateKey.pem", "rb") as f:
        privateKey = serialization.load_pem_private_key(
            f.read(),
            password=None 
        )
        
    with open("MasterECCPublicKey.pem", "rb") as f:
        publicKey = serialization.load_pem_public_key(f.read())

#Test certificate creation
CreateUserCertificate("John Smith", 
    "JohnSmith1", 
    "Head Engineer", 
    "ExampleB64", 
    [["Engineering LVL1", "WRITE"],["Engineering LVL2", "WRITE"],["Management LVL1", "READ"]], 
    "01/01/30", 
    {"Mon" : True, "Tue" : True, "Wed" : True, "Thu" : True, "Fri" : True, "Sat" : False, "Sun" : False},
    "09:00",
    "17:00",
    "ECDSA",
    "RS3",
    "29/12/25",
    12345,
    1)

CreateResourceCertificate(
    "Management Resource",
    "ManagementResource1",
    "Example2B64",
    "ECDSA",
    "RS3",
    "29/12/25",
    "01/01/30",
    12345,
    1)
