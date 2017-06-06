# Easy Digital Signature
A simple utility to create digital signatures using PKI certificates/keys. The utility has two functions - (1) generate digital signature bytes for a given file and save it as a binary file, and (2) extract the public certificate only from a X509 certificate and save it in PEM format. 

## PKI certificates
The utility can access X509 certificates that are in the Windows certificate store for a given user. Only certificates that include the private key will be shown. The utility can also access smartcards that have registered their CSP with Windows using the Minidriver or CNG API. 

## Installation
The user may download the entire project via Git and build it using Visual Studio. Note: The project may need a change in configuration to point to the correct project folder. 
Alernatively, the user may simply run the executable file found at "/WpfApp2/bin/Release/DigitalSignatures.exe".

## Requirements
The utility was built and tested on Windows 7. It is recommended that only Windows 7 or later versions be used. No testing has yet been done for other operating systems. 

## How to Use
After launching the utility, a list of certificates available for signing files will be shown. After selecting the correct certificate, the user may select which file to create a digital signature for. The binary file containing the signature bytes will be saved in the same folder as the file (with .sign extension). Another feature available is to extract the X509 public certificate in the Downloads folder (with .crt extension). 

## Security
The signing is done in compliance with Windows security standards. For smartcards that allow on-board crypto functions and signing, and register their crypto functions with Windows, the same procedure will be followed within this utility. At no point is the private key extracted or saved in the file system. 

## Future Work 
(Contributions welcome)
- Inclusion of OpenSC smartcard library
- Utilities for other operating systems like Mac OS and Linux
