
import sys
import keyring
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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

def WizardInitialisation(masterPassword):
    ph = PasswordHasher()
    keyring.set_password("Decentralised-File-System", "master", ph.hash(masterPassword))

    CreateECCKeypair()

class SettingsPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Configuration")
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter master password:"))
        self.usernameLine = QLineEdit()
        layout.addWidget(self.usernameLine)
        self.setLayout(layout)
        self.registerField("password*", self.usernameLine)  # * means required

#Stylesheet
background = "#575f60"
primary = "#e7dfde"
highlight = "#e83151"
stylesheet = f"""
* {{
    background-color: {background};
}}

QWizard QFrame {{
    background-color: {background};
}}

QWizardPage {{
    background-color: {background};
}}

QLabel {{
    color: {primary};
    font-size : 30px;
}}

QLineEdit {{
    background-color: {highlight};
    color: {primary};
}}

QWizard QPushButton {{
    background-color: {highlight};
    color: white;
    border: none;
    padding: 6px 14px;
    border-radius: 6px;
    min-width: 80px;
}}

QWizard QPushButton:hover {{
    background-color: #c91f3e;
}}

QWizard QPushButton:pressed {{
    background-color: #a3152f;
}}

"""

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion") 
    app.setStyleSheet(stylesheet)
    
    wizard = QWizard()
    wizard.setWizardStyle(QWizard.ModernStyle)
    wizard.setOption(QWizard.NoBackButtonOnStartPage, True)
    wizard.addPage(SettingsPage())
    wizard.setWindowTitle("Semi - Decentralised Gateway Setup Wizard")
    
    if wizard.exec_() == QWizard.Accepted:
        
        password = wizard.field("password")
        WizardInitialisation(password)
        sys.exit()
    
    sys.exit(app.exec_())