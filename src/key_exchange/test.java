package key_exchange;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class test {
    public static void main(String[] args) {
    	
    	// constructor 1
    	String algorithm = "RSA";
		String signatureAlg = "SHA256withRSA";
		int keySize = 4096;
		int certExpireInDays = 365;
		String commonName = "CN=KeyManagerTest";	
    	KeyManager keyManager = new KeyManagerImpl(
    			algorithm, 
    			signatureAlg,
    			keySize,
    			certExpireInDays,
    			commonName);
    	
    	// constructor 2:
    	// KeyManager keyManager = new KeyManagerImpl();
    	
    	String privKeyFileName = "/tmp/privatekey.pem";
    	String certificateFileName = "/tmp/certificate.pem";
    	keyManager.generateKeyCertificate(privKeyFileName, certificateFileName);
    	PrivateKey privateKey = null;
    	PublicKey publicKey = null;
		try {
			privateKey = keyManager.loadPrivateKeyFromRSAPEM(privKeyFileName);
	    	publicKey = keyManager.loadPublicKeyFromRSA_X509_CertificatePEM(certificateFileName);
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		}
    	String plainText = "MY PLAIN TEXT";
    	String encryptedBase64Str;
    	
    	try {
    		encryptedBase64Str = keyManager.encryptTextBase64(plainText.getBytes(), publicKey);
    		System.out.println("Encrypted text: " + encryptedBase64Str);
    		String decryptedStr = keyManager.decryptTextBase64(encryptedBase64Str.getBytes(), privateKey);
    		System.out.println("Decrypted text: " + decryptedStr);
    	    
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
    	}    	
    	
    }

}
