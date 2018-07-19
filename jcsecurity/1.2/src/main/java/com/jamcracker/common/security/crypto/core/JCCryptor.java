package com.jamcracker.common.security.crypto.core;

import java.security.InvalidKeyException;
import java.security.Security;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.jamcracker.common.exception.JCFaultCode;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;

/**
 * Responsible for cryptographic operations extends core class
 * @author kkpushparaj
 *
 */
public class JCCryptor extends JCCryptorBase implements ICryptor {
	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger	.getLogger(JCCryptor.class.getName());
	
	//Constructor init's bouncy castle as provider
	public JCCryptor() {
		Security.addProvider(new BouncyCastleProvider());
	}

	// Generates key in Hex format by supplying algorithm and bit size 
	@Override
	public String generateSecretKey(final JCCryptoAlgorithm algorithm,final int bit) throws JCCryptoException {
		final Generator generator = new Generator(algorithm, JCCryptoConstants.BIT256);
		return generator.generateKey();
	}

	//Encrypts string in base64 encoded format by supplying by supplying algorithm and key in Hex format
	@Override
	public String encrypt(final JCCryptoAlgorithm algorithm,final  String key, final String data) throws JCCryptoException, InvalidKeyException {
		byte[] cipherBytes = data.getBytes();
		return new String(Base64.encodeBase64(doCrypt(algorithm, key, cipherBytes, CRYTO_MODE.ENCRYPT)));
	}

	//Decrypts string by supplying algorithm and key in Hex format
	@Override
	public String decrypt(final JCCryptoAlgorithm algorithm,final String key, final String data)
			throws JCCryptoException, InvalidKeyException {
		byte[] cipherBytes = Base64.decodeBase64(data.getBytes());
		return new String(doCrypt(algorithm, key, cipherBytes, CRYTO_MODE.DECRYPT));
	}

	//Generates SALT by supplying algorithm and size
	@Override
	public String generateSalt(final JCCryptoAlgorithm algorithm,final int size)
			throws JCCryptoException {
		final Generator generator = new Generator(algorithm,size);
		return generator.generateSalt();
	}

	//Generates HASH by supplying algorithm 
	@Override
	public String generateHash(final JCCryptoAlgorithm algorithm,final String hash) throws JCCryptoException {
	
		return new String(Hex.encodeHex(doHash(algorithm, hash)));
	}

	//Generates HMAC string in base64 format by supplying algorithm and SALT
	@Override
	public String generateHMAC(final JCCryptoAlgorithm algorithm,final String salt, final String hash)
			throws JCCryptoException, InvalidKeyException {
		
		return doHMac(algorithm,salt,hash);
	}

	//generates one time pin
	@Override
	public String generateOneTimePin(JCCryptoAlgorithm algorithm,
			Long[] entropy, int size) throws JCCryptoException {
		
		final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
			 
//		setAlgorithm(algorithm);
		String salt = generateSalt(JCCryptoAlgorithm.HMACSHA1, JCCryptoConstants.SALTSIZE1);
		
		long T0 = 0;
        long X = 30;
        long time = System.currentTimeMillis();
 
        String steps = "0";
 		
		long T = (time - T0) / X;
        steps = Long.toHexString(T).toUpperCase();
 
        //entropy addtions
        for (Long entVal : entropy) {
        	steps += Long.toHexString(entVal).toUpperCase();
		}
        
        String hmac=new String();
		try {
			hmac = generateHMAC(JCCryptoAlgorithm.HMACSHA1,salt, steps);
		} catch (InvalidKeyException e) {
			JCCryptor.LOGGER.error("Issue in generating one time pin key : "	+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		
		byte[] hmacBytes = hmac.getBytes();
		
		//Calculate offset
		int offset = hmacBytes[hmacBytes.length - 1] & 0xf;
	    
		//Calculate binary
		int binary = ((hmacBytes[offset] & 0x7f) << 24) |
	            ((hmacBytes[offset + 1] & 0xff) << 16) |
	            ((hmacBytes[offset + 2] & 0xff) << 8| 
	            (hmacBytes[offset + 3] & 0xff));
	 
		//OTP generation
	    int otp = binary % DIGITS_POWER[size];
       
	    String result = Integer.toString(otp);
	    //padding
        while (result.length() < size) {
            result = "0" + result;
        }
		return result;
	}
}