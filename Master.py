import os
import sys
import json
import base64
import logging
import keyring
import colorlog
from datetime import *
from PyQt5 import QtCore
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from argon2 import PasswordHasher
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

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

def CreateUserCertificate(name : str, ID : str, title : str, publicKeyPath : str, permissions : list, expiryDate : str, algorithmUsed : str, issuerID : str, issueDate : str, serial : int, version : int):
    permissionsDict = dict()
    
    for permission in permissions:
        permissionsDict[permission[0]] = permission[1]
        
    with open(publicKeyPath, "rb") as f:
        pemPublic = f.read()

    publicKey = serialization.load_pem_public_key(pemPublic)

    publicDer = publicKey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    publicKeyBytesB64 = base64.b64encode(publicDer).decode()
    
    userDict = {
        "Name" : name,
        "ID" : ID,
        "Title" : title,
        "Public Key" : publicKeyBytesB64,
        "Permissions" : permissionsDict,
        "Expiry Date" : expiryDate,
        "Algorithm Used" : algorithmUsed,
        "Issuer" : issuerID,
        "Issue Date" : issueDate,
        "Serial" : serial,
        "Certificate Version" : version
    }
    
    #Signing the user
    signatureBytes = privateKey.sign(
        json.dumps(userDict).encode(),
        ec.ECDSA(hashes.SHA256())
    )
    
    userDict["Signature"] = base64.b64encode(signatureBytes).decode()
    with open(f"User{secure_filename(ID)}Certificate.json", "w") as f:
        json.dump(userDict, f, indent=4)

def CreateResourceCertificate(name : str, ID : str, publicKeyPath : str, algorithmUsed : str, issuerID : str, issueDate : str, expiryDate : str, serial : int, version : int, ):
    
    with open(publicKeyPath, "rb") as f:
        pemPublic = f.read()

    publicKey = serialization.load_pem_public_key(pemPublic)

    publicDer = publicKey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    publicKeyBytesB64 = base64.b64encode(publicDer).decode()
    
    resourceDict = {
        "Name" : name,
        "ID" : ID,
        "Public Key" : publicKeyBytesB64,
        "Algorithm Used" : algorithmUsed,
        "Issuer" : issuerID,
        "Issue Date" : issueDate,
        "Expiry" : expiryDate,
        "Serial" : serial,
        "Certificate Version" : version,
    }
    
    signatureBytes = privateKey.sign(
        json.dumps(resourceDict).encode(),
        ec.ECDSA(hashes.SHA256())
    )
    
    resourceDict["Signature"] = base64.b64encode(signatureBytes).decode()
    with open(f"Resource{secure_filename(ID)}Certificate.json", "w") as f:
        json.dump(resourceDict, f, indent=4)

if(not os.path.exists("MasterECCPrivateKey.pem")):
   logger.critical("No keypair exists!")
else:
    with open("MasterECCPrivateKey.pem", "rb") as f:
        privateKey = serialization.load_pem_private_key(
            f.read(),
            password=None 
        )
        
    with open("MasterECCPublicKey.pem", "rb") as f:
        publicKey = serialization.load_pem_public_key(f.read())

def CreateLogKey():
    if(os.path.exists("MasterLogPrivateKey.key")):
        print(f"Exists")
        with open("MasterLogPrivateKey.key", "rb") as f:
            privateKey = x25519.X25519PrivateKey.from_private_bytes(f.read())

        with open("MasterLogPublicKey.key", "rb") as f:
            publicKey = x25519.X25519PublicKey.from_public_bytes(f.read())
        
    else:
        privateKey = x25519.X25519PrivateKey.generate()
        publicKey = privateKey.public_key()

        # Save private key
        with open("MasterLogPrivateKey.key", "wb") as f:
            f.write(
                privateKey.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save public key
        with open("MasterLogPublicKey.key", "wb") as f:
            f.write(
                publicKey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
    
    return privateKey, publicKey

def DecodeLog(logPath):
    out = []
    with open(logPath, "r") as f:

        lines = f.readlines()
        
        ephemeralKeyLine = lines.pop(0).strip().split(" - ")
        ephemeralPublicKey = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(ephemeralKeyLine[1]))
        sharedSecret = logPrivateKey.exchange(ephemeralPublicKey)
        derivedKey = AESGCM(HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Log Encryption"
        ).derive(sharedSecret))
        
        for line in lines:
            if(line == "\n"):
                continue
            line = line.strip().split(" - ")
            nonce = base64.b64decode(line[0])
            ciphertext = base64.b64decode(line[1])
            out.append(derivedKey.decrypt(nonce, ciphertext, None).decode())

    return out

def CreateClientLogin(clientID, clientPassword):
    ph = PasswordHasher()
    keyring.set_password("Decentralised-File-System", clientID, ph.hash(clientPassword))

def AttemptMasterLogin(password):
    passwordHash = keyring.get_password("Decentralised-File-System", "master")
    ph = PasswordHasher()
    try:
        ph.verify(passwordHash, password)
    except:
        sys.exit()

#Test certificate creation
"""CreateUserCertificate("John Smith", 
    "JohnSmith1", 
    "Head Engineer", 
    "ExampleB64", 
    [["Engineering LVL1", "WRITE"],["Engineering LVL2", "WRITE"],["Management LVL1", "READ"]], 
    "01/01/30", 
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

"""

logPrivateKey, logPublicKey = CreateLogKey()


#QT

def OnTXTFileDrop(path):
    print(path)

#Stylesheet
background = "#f5f5eb"
primary = "#696969"
highlight = "#1f232d"

logColourDict = {
    "INFO" : "#f5f5eb",
    "WARNING" : "#e8af35",
    "ERROR" : "#a3140a"
}

stylesheet = f"""
* {{
    background-color: {background};
    color : {background};
}}

QFrame {{
    background-color: {background};
}}

QLabel {{
    color : {highlight};
    font-size : 30px;
}}

QLabel[title="true"] {{
    font-size : 50px;
    background-color : {highlight};
    color : {background};
    padding : 5px;
    margin : 5px;
    border-radius : 20px;
}}

QLineEdit {{
    background-color: {highlight};
}}

QPushButton {{
    background-color: {highlight};
    border: none;
    padding: 6px 14px;
    border-radius: 6px;
    min-width: 80px;
}}

QPushButton:hover {{
    background-color: #c91f3e;
}}

QPushButton:pressed {{
    background-color: #a3152f;
}}

QPushButton[primary="true"] {{
    min-width : 350px;
    max-width : 350px;
    min-height : 150px;
    max-height : 150px;
    font-size : 30px;
}}

QWidget[primaryButtons="true"] {{
    background-color : {primary};
    border-radius: 20px;
}}

QWidget[uploadSection="true"] {{
    background-color : {highlight};
    color : {background};
    border-radius : 15px;
    font-size : 40px;
}}

QPlainTextEdit {{
    background-color : {highlight};
    color : {background};
    border-radius : 15px;
    font-size : 25px;
}}

*[clientInput="true"] {{
    color : {background};
}}

QLineEdit[clientInput="true"] {{
    background-color : {background};
    color : {highlight};
    font-size : 20px;
    min-width : 200px;
    max-width : 200px;
}}

QWidget[clientCertPage="true"] {{
    background-color:{highlight};
    border-radius : 15px;
}}

QLabel[clientInput="true"] {{
    background-color : {highlight};
}}

QDateEdit[clientInput="true"] {{
    color : {highlight};
    font-size : 20px;
    min-width : 200px;
    max-width : 200px;
}}

QCalendarWidget QWidget{{
    color : {highlight};
    font-size : 20px;
}}

QComboBox {{
    color : {highlight};
}}

"""

class LoginPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Configuration")
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter master password:"))
        self.usernameLine = QLineEdit()
        layout.addWidget(self.usernameLine)
        self.setLayout(layout)
        self.registerField("password*", self.usernameLine)  # * means required

class TXTDropArea(QLabel):
    fileDropped = pyqtSignal(str)

    def __init__(self):
        super().__init__("Drop TXT log file here ⤒")
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].toLocalFile().lower().endswith(".txt"):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        path = event.mimeData().urls()[0].toLocalFile()
        self.fileDropped.emit(path)
        
class ClientPermission():
    def __init__(self):
        self.widget = QWidget()
        self.widget.setProperty("isPermissionWidget", True)
        layout = QHBoxLayout()
        self.permissionLabel = QLineEdit()
        self.permissionLabel.setPlaceholderText("Permission")
        self.permission = QComboBox()
        self.permission.addItems(["READ", "WRITE"])
        layout.addWidget(self.permissionLabel)
        layout.addWidget(self.permission)
        self.widget.setLayout(layout)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        def HandleLog(path):
            logs = DecodeLog(path)
            self.logDisplayWidget.setReadOnly(True)
            
            cursor = self.logDisplayWidget.textCursor()
            for log in logs:
                if("INFO" in log):
                    logColor = logColourDict["INFO"]
                else:
                    logColor = logColourDict["WARNING"] if "WARNING" in log else logColourDict["ERROR"]
                
                cursor.movePosition(QTextCursor.End)
                fmt = QTextCharFormat()
                fmt.setForeground(QColor(logColor))
                cursor.insertText(log + "\n", fmt)
                self.logDisplayWidget.setTextCursor(cursor)
            
            self.loggingStack.setCurrentWidget(self.logDisplayWidget)

        self.setWindowTitle("PyQt5 QSS App")
        self.resize(400, 300)

        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)

        # Main vertical layout
        mainLayout = QVBoxLayout()
        centralWidget.setLayout(mainLayout)

        # Header - top center
        headerLayout = QHBoxLayout()
        self.label = QLabel("Huginn-Munnin - Master")
        self.label.setProperty("title", True)
        self.label.setAlignment(Qt.AlignCenter)
        headerLayout.addWidget(self.label)
        mainLayout.addLayout(headerLayout)

        # Bottom section - left buttons + right content
        bottomLayout = QHBoxLayout()
        mainLayout.addLayout(bottomLayout)

        # Left buttons
        leftWidget = QWidget()
        leftWidget.setProperty("primaryButtons", True)
        leftLayout = QVBoxLayout()
        leftWidget.setLayout(leftLayout)
        leftLayout.setProperty("primaryButtons", True)
        self.clientLoginButton = QPushButton("Create Client Login")
        self.clientCertificateButton = QPushButton("Create Client Cert")
        self.resourceCertificateButton = QPushButton("Create Resource Cert")
        self.decodeLogButton = QPushButton("Decode Log")
        buttons = [self.clientLoginButton, self.clientCertificateButton, self.resourceCertificateButton, self.decodeLogButton]
        
        leftLayout.addStretch(1)
        for button in buttons:
            button.setProperty("primary", True)
            button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
            leftLayout.addWidget(button, alignment=Qt.AlignCenter)
            leftLayout.addStretch(1)
        leftLayout.addStretch()  # push buttons to top
        bottomLayout.addWidget(leftWidget)

        # Right/main content area
        rightLayout = QVBoxLayout()
        stack = QStackedWidget()
        
        #Default
        defaultPage = QWidget()
        defaultLayout = QVBoxLayout()
        defaultWidget = QLabel("Select a button to begin")
        defaultLayout.addWidget(defaultWidget)
        defaultPage.setLayout(defaultLayout)
        
        #Logging
        loggingPage = QWidget()

        self.loggingStack = QStackedWidget()
        uploadWidget = TXTDropArea()
        uploadWidget.fileDropped.connect(HandleLog)
        uploadWidget.setProperty("uploadSection", True)
        self.loggingStack.addWidget(uploadWidget)
        
        self.logDisplayWidget = QPlainTextEdit()
        self.loggingStack.addWidget(self.logDisplayWidget)
        
        loggingLayout = QVBoxLayout()
        loggingLayout.addWidget(self.loggingStack)
        loggingPage.setLayout(loggingLayout)
        
        #Client Cert
        clientCertPage = QWidget()
        clientCertPage.setProperty("clientCertPage", True)
        clientCertLayout = QHBoxLayout() 
        
        clientCertLeftWidget = QWidget()
        clientCertLeftWidget.setProperty("clientCertPage", True)
        
        clientCertRightScroll = QScrollArea()
        clientCertRightScroll.setWidgetResizable(True)
        clientCertRightScroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        clientCertRightWidget = QWidget()
        #clientCertRightWidget.setWidgetResizable(True)
        #clientCertRightWidget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        clientCertRightWidget.setProperty("clientCertPage", True)
        
        clientCertLeftLayout = QVBoxLayout()
        clientCertRightLayout = QVBoxLayout() 
        clientCertRightLayout.setAlignment(Qt.AlignTop)  
        
        clientUsernameInput = QLineEdit()
        clientIDInput = QLineEdit()
        clientTitleInput = QLineEdit()
        clientPublicKeyPathInput = QLineEdit()
        
        methodUsed = "ECDSA"
        clientIssuerInput = QLineEdit()
        issueDate = date.today().strftime("%d/%m/%Y")
        clientExpiryDate = QDateEdit()
        clientSerial = QLineEdit()
        clientCertificateVersion = QLineEdit()
        
        clientInputs = [
            ["Client Name", clientUsernameInput], 
            ["Client ID", clientIDInput], 
            ["Client Title", clientTitleInput],
            ["Client Public Key Path", clientPublicKeyPathInput], 
            ["Issuer ID", clientIssuerInput], 
            ["Cert Expiry Date", clientExpiryDate], 
            ["Serial No.", clientSerial], 
            ["Cert Version", clientCertificateVersion]
        ]
        
        #Date preformatting
        today = date.today()
        clientExpiryDate.setCalendarPopup(True)
        clientExpiryDate.setMinimumDate(QDate(today.year, today.month, today.day))
        clientExpiryDate.setMaximumDate(QDate(2099,12,31))
        clientExpiryDate.setDisplayFormat("dd/MM/yy")
        clientExpiryDate.setAlignment(Qt.AlignCenter)
        
        clientCertLeftLayout.addStretch(1)
        for clientInputSet in clientInputs:
            title = clientInputSet[0]
            clientInput = clientInputSet[1]
            if(type(clientInput) == QLineEdit):
                clientInput.setAlignment(Qt.AlignCenter)
            titleLabel = QLabel(title)
            titleLabel.setProperty("clientInput", True)
            clientInput.setProperty("clientInput", True)
            clientCertLeftLayout.addWidget(titleLabel, alignment=Qt.AlignCenter)
            clientCertLeftLayout.addWidget(clientInput, alignment=Qt.AlignCenter)
            clientCertLeftLayout.addStretch(1)

        createClientCertButton = QPushButton("Create Client Cert")
        clientCertLeftLayout.addWidget(createClientCertButton, alignment=Qt.AlignCenter)
        clientCertLeftLayout.addStretch(1)
        
        #Permission sections
        clientCertPermissions = [ClientPermission()]

        clientCertbuttonContainer = QFrame()
        clientCertbuttonLayout = QHBoxLayout()
        clientCertAddPermissionButton = QPushButton("Add permission")
        clientCertRemovePermissionButton = QPushButton("Remove permission")
        clientCertbuttonLayout.addWidget(clientCertAddPermissionButton)
        clientCertbuttonLayout.addWidget(clientCertRemovePermissionButton)
        clientCertbuttonContainer.setLayout(clientCertbuttonLayout)
        clientCertRightLayout.addWidget(clientCertbuttonContainer)

        for permission in clientCertPermissions:
            clientCertRightLayout.addWidget(permission.widget, alignment=Qt.AlignCenter)

        clientCertLeftWidget.setLayout(clientCertLeftLayout)  
        clientCertRightWidget.setLayout(clientCertRightLayout)
        clientCertLayout.addWidget(clientCertLeftWidget)
        clientCertRightScroll.setWidget(clientCertRightWidget)
        clientCertLayout.addWidget(clientCertRightScroll)      
        clientCertPage.setLayout(clientCertLayout)
        
        def AddPermission():
            newPermission = ClientPermission()
            clientCertPermissions.append(newPermission)
            clientCertRightLayout.addWidget(newPermission.widget, alignment=Qt.AlignCenter)
        
        def RemovePermission():
            length = clientCertRightLayout.count()
            if(length > 1):
                widget = clientCertRightLayout.takeAt(length - 1).widget()
                widget.setParent(None)
                widget.deleteLater()
        
        clientCertAddPermissionButton.clicked.connect(AddPermission)
        clientCertRemovePermissionButton.clicked.connect(RemovePermission)
        createClientCertButton.clicked.connect(
            lambda: CreateUserCertificate(
                clientUsernameInput.text(),
                clientIDInput.text(),
                clientTitleInput.text(),
                clientPublicKeyPathInput.text(),
                list([[permission.permissionLabel.text(), permission.permission.currentText()] for permission in clientCertPermissions]),
                clientExpiryDate.date().toString("dd/MM/yy"), 
                methodUsed,
                clientIssuerInput.text(),
                issueDate,
                int(clientSerial.text()),
                int(clientCertificateVersion.text())
            )
        )
        
        #Client Login
        clientLoginPage = QWidget()
        clientLoginLayout = QVBoxLayout()
        
        clientLoginIDLabel = QLabel("Client Username")
        clientLoginPasswordLabel = QLabel("Client Password")
        clientLoginIDInput = QLineEdit()
        clientLoginPasswordInput = QLineEdit()
        clientLoginCreateLoginButton = QPushButton()
        
        clientLoginCreateLoginButton.clicked.connect(
            lambda : CreateClientLogin(clientLoginIDInput.text(), clientLoginPasswordInput.text())
        )
        
        clientLoginLayout.addWidget(clientLoginIDLabel)
        clientLoginLayout.addWidget(clientLoginIDInput)
        clientLoginLayout.addWidget(clientLoginPasswordLabel)
        clientLoginLayout.addWidget(clientLoginPasswordInput)
        clientLoginLayout.addWidget(clientLoginCreateLoginButton)
        
        clientLoginPage.setLayout(clientLoginLayout)
        
        #Resource Cert 
        resourceCertPage = QWidget()
        resourceCertLayout = QVBoxLayout()
        
        resourceCertNameInput = QLineEdit()
        resourceCertIDInput = QLineEdit()
        resourceCertPublicKeyPath = QLineEdit()
        resourceCertIssuerIDInput = QLineEdit()
        resourceCertExpiryDateInput = QDateEdit()
        resourceCertSerialInput = QLineEdit()
        resourceCertVersionInput = QLineEdit()
        
        resourceCertExpiryDateInput.setCalendarPopup(True)
        resourceCertExpiryDateInput.setMinimumDate(QDate(today.year, today.month, today.day))
        resourceCertExpiryDateInput.setMaximumDate(QDate(2099,12,31))
        resourceCertExpiryDateInput.setDisplayFormat("dd/MM/yy")
        resourceCertExpiryDateInput.setAlignment(Qt.AlignCenter)
        
        resourceCertInputs = [
            ["Resource Name", resourceCertNameInput],
            ["Resource ID", resourceCertIDInput],
            ["Resource Public Key Path", resourceCertPublicKeyPath],
            ["Issuer ID", resourceCertIssuerIDInput],
            ["Cert Expiry Date", resourceCertExpiryDateInput], 
            ["Serial No.", resourceCertSerialInput], 
            ["Cert Version", resourceCertVersionInput] 
        ]
        
        resourceCertLayout.addStretch(1)
        for resourceInput in resourceCertInputs:
            title = QLabel(resourceInput[0])
            resourceCertLayout.addWidget(title)
            resourceCertLayout.addWidget(resourceInput[1])
            resourceCertLayout.addStretch(1)
        
        createResourceCertButton = QPushButton("Create Cert")
        createResourceCertButton.clicked.connect(
            lambda : CreateResourceCertificate(
                resourceCertNameInput.text(),
                resourceCertIDInput.text(),
                resourceCertPublicKeyPath.text(),
                methodUsed,
                resourceCertIssuerIDInput.text(),
                issueDate,
                resourceCertExpiryDateInput.date().toString("dd/MM/yy"),
                int(resourceCertSerialInput.text()),
                int(resourceCertVersionInput.text())
            )
        )
        resourceCertLayout.addWidget(createResourceCertButton)
        resourceCertLayout.addStretch(1)
        
        resourceCertPage.setLayout(resourceCertLayout)
        
        #Common
        stack.addWidget(defaultPage)
        stack.addWidget(loggingPage)
        stack.addWidget(clientCertPage)
        stack.addWidget(clientLoginPage)
        stack.addWidget(resourceCertPage)
        rightLayout.addWidget(stack)
        
        bottomLayout.addLayout(rightLayout)
        bottomLayout.setStretch(0, 1)
        bottomLayout.setStretch(1, 4)
        
        self.decodeLogButton.clicked.connect(
            lambda : stack.setCurrentWidget(loggingPage)
        )
        self.clientCertificateButton.clicked.connect(
            lambda : stack.setCurrentWidget(clientCertPage)
        )
        
        self.clientLoginButton.clicked.connect(
            lambda : stack.setCurrentWidget(clientLoginPage)
        )
        
        self.resourceCertificateButton.clicked.connect(
            lambda : stack.setCurrentWidget(resourceCertPage)
        )
        
app = QApplication(sys.argv)
app.setStyle("Fusion") 
app.setStyleSheet(stylesheet)
wizard = QWizard()
wizard.setWizardStyle(QWizard.ModernStyle)
wizard.setOption(QWizard.NoBackButtonOnStartPage, True)
wizard.addPage(LoginPage())
wizard.setWindowTitle("Semi - Decentralised Gateway Setup Wizard")

if wizard.exec() != QWizard.Accepted:
    sys.exit()

password = wizard.field("password")
AttemptMasterLogin(password)

window = MainWindow()
window.showMaximized()
sys.exit(app.exec_())

#CreateClientLogin("JohnSmith1", "John123")