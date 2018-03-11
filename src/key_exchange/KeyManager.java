package key_exchange;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyManager {
	/**
	 * Generate PrivateKey and Certificate 
	 *
	 * @param  privKeyFileName  output file name of private key 
	 * @param  certFileName output file name of certificate
	 * @return      None
	 */	
	public void generateKeyCertificate(String privKeyFileName, String certFileName);
	
	/**
	 * Generate public key from a RSA X.509 certificate file 
	 *
	 * @param  certFileName input file name of certificate
	 * @return      PublicKey
	 */	
	public PublicKey loadPublicKeyFromRSA_X509_CertificatePEM(String certFileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;

	/**
	 * Generate private key from a RSA PEM file 
	 *
	 * @param  privateKeyFileName input file name of private key
	 * @return      PrivateKey
	 */		
	public PrivateKey loadPrivateKeyFromRSAPEM(String privateKeyFileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;
	
	/**
	 * Encrypt a byte[] with given public key, and encode it with Base64
	 *
	 * @param  text input byte[] from text that needs to be encrypted
	 * @param  key public key that is used to encrypt the given byte[]
	 * @return      Base64 encoded string of encrypted byte[]
	 */	
    public String encryptTextBase64(byte[] text, PublicKey key) throws Exception;

	/**
	 * Decrypt a byte[] which is Base64 encoded with given private key
	 *
	 * @param  text input byte[] that is Base64 encoded, which needs to be decrypted
	 * @param  key private key that is used to decrypt the given byte[]
	 * @return      Plain text of the encrypted byte[]
	 */	    
    public String decryptTextBase64(byte[] text, PrivateKey key) throws Exception;
}
