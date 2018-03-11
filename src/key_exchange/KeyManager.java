package key_exchange;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyManager {
	public void generateKeyCertificate(String privKeyFileName, String certFileName);
	public PublicKey loadPublicKeyFromRSA_X509_CertificatePEM(String certFileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;
	public PrivateKey loadPrivateKeyFromRSAPEM(String fileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;
    public String encryptTextBase64(byte[] text, PublicKey key) throws Exception;
    public String decryptTextBase64(byte[] text, PrivateKey key) throws Exception;
}
