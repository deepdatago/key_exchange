# RSA X.509 Certificate and Private Key Manager in JAVA
version 0.0.1 by Mingjun Zhu (deepdatago@gmail.com)

This library is based on [Bouncy Castle 1.59](https://www.bouncycastle.org/latest_releases.html)

The key features list:
* public void generateKeyCertificate(String privKeyFileName, String certFileName);
* public PublicKey loadPublicKeyFromRSA_X509_CertificatePEM(String certFileName) 
* public PrivateKey loadPrivateKeyFromRSAPEM(String privateKeyFileName) 
* public String encryptTextBase64(byte[] text, PublicKey key);
* public String decryptTextBase64(byte[] text, PrivateKey key);

### Sample Usage
Generate private key and certificate
```
KeyManager keyManager = new KeyManagerImpl();
String privKeyFileName = "/tmp/privatekey.pem";
String certificateFileName = "/tmp/certificate.pem";
keyManager.generateKeyCertificate(privKeyFileName, certificateFileName);
```
Load private key and public key
```
privateKey = keyManager.loadPrivateKeyFromRSAPEM(privKeyFileName);
publicKey = keyManager.loadPublicKeyFromRSA_X509_CertificatePEM(certificateFileName);
```

Encrypt and Decrypt plain text
```
String plainText = "MY PLAIN TEXT";
String encryptedBase64Str;
encryptedBase64Str = keyManager.encryptTextBase64(plainText.getBytes(), publicKey);
String decryptedStr = keyManager.decryptTextBase64(encryptedBase64Str.getBytes(), privateKey);
```

