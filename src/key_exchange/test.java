package key_exchange;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

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
    	
    	String myKey = "12345678901234567890123456789012";
    	SecretKeySpec key = new SecretKeySpec(myKey.getBytes(), "AES");

        Cipher cipher = null;
		try {
	    	// int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
	    	// System.out.println("max allowed length: " + maxKeyLen);
	    	
			
			cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
	        cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        byte[] cipherText = new byte[cipher.getOutputSize(plainText.length())];
        int ctLength = 0;
		try {
			ctLength = cipher.update(plainText.getBytes(), 0, plainText.length(), cipherText, 0);
	        ctLength += cipher.doFinal(cipherText, ctLength);
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e)
		{
			e.printStackTrace();
			
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String encodedEncryptedStr = new String(Base64.getEncoder().encode(cipherText));
		System.out.println(encodedEncryptedStr);
        // System.out.println(new String(cipherText));
        // System.out.println(ctLength);

        // decryption pass
        byte[] decryptedPlainText = null;
        int ptLength = 0;
        try {
			cipher.init(Cipher.DECRYPT_MODE, key);
	        decryptedPlainText = new byte[cipher.getOutputSize(ctLength)];
	        ptLength = cipher.update(Base64.getDecoder().decode(encodedEncryptedStr), 0, ctLength, decryptedPlainText, 0);
	        ptLength += cipher.doFinal(decryptedPlainText, ptLength);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e)
		{
			e.printStackTrace();
			
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        System.out.println("decrypted:" + new String(decryptedPlainText));    	
    }

}
