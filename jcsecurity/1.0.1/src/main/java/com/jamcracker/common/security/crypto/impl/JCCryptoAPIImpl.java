package com.jamcracker.common.security.crypto.impl;

import java.security.InvalidKeyException;

import com.jamcracker.common.security.crypto.ICryptoAPI;
import com.jamcracker.common.security.crypto.JCCryptoType;
import com.jamcracker.common.security.crypto.core.ICryptor;
import com.jamcracker.common.security.crypto.core.JCCryptoAlgorithm;
import com.jamcracker.common.security.crypto.core.JCCryptoConstants;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
/**
 * Implementation class for High level cryptographic operations
 * @author kkpushparaj
 *
 */
public class JCCryptoAPIImpl implements ICryptoAPI {

	/**
	 * Injects the JCCryptor class through springs.
	 */
	private ICryptor cryptor;
	
	
	/**
	 * This methods returns the ICryptor implementation (JCCryptor)
	 * object reference.
	 */
	public ICryptor getCryptor() {
		return cryptor;
	}

	/**
     * This methods sets the ICryptor implementation object reference
     * while initiating JCCryptoAPIImpl bean in jccrypto-context.xml 
     * @param cryptor
     */
	public void setCryptor(ICryptor cryptor) {
		this.cryptor = cryptor;
	}

	/*
	 * Used to generate the salt in given size
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#generateSalt(com.jamcracker.common.security.crypto.JCCryptoType)
	 */
	@Override
	public String generateSalt(final JCCryptoType cryptoType)
			throws JCCryptoException {
		String salt=new String();
		switch (cryptoType) {
		case USER_PASSWORD:
			salt = cryptor.generateSalt(JCCryptoAlgorithm.HMACSHA512, JCCryptoConstants.SALTSIZE4);
			break;
		default:
			salt = cryptor.generateSalt(JCCryptoAlgorithm.HMACSHA512, JCCryptoConstants.SALTSIZE1);
			break;
		}
		return salt;
	}

	/*
	 * Used to generate a HMAC by providing salt. Gives in base64 format.
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#generateHMAC(com.jamcracker.common.security.crypto.JCCryptoType, java.lang.String, java.lang.String)
	 */
	@Override
	public String generateHMAC(final JCCryptoType cryptoType, final String salt, final String toBeHashed)
			throws JCCryptoException, InvalidKeyException {
		String hash=new String();
		switch (cryptoType) {
		case USER_PASSWORD:
			hash = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, salt, toBeHashed);
			break;
		default:
			hash = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, salt, toBeHashed);
			break;
		}
		return hash;
	}

	/*
	 * Used to generate cryptographic keys in hex format
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#generateKey(com.jamcracker.common.security.crypto.JCCryptoType)
	 */
	@Override
	public String generateKey(final JCCryptoType cryptoType) throws JCCryptoException {
		String key = new String();
		switch (cryptoType) {
		case CREDIT_CARD:
			key = cryptor.generateSecretKey(JCCryptoAlgorithm.AES,JCCryptoConstants.BIT256);
			break;
		case PERSONAL_DATA:
			key = cryptor.generateSecretKey(JCCryptoAlgorithm.AES,JCCryptoConstants.BIT256);
			break;
		case SERVICE_PASSWORD:
			key = cryptor.generateSecretKey(JCCryptoAlgorithm.AES,JCCryptoConstants.BIT256);
			break;
		case URL:
			key = cryptor.generateSecretKey(JCCryptoAlgorithm.AES,JCCryptoConstants.BIT256);
			break;	
		default:
			key = cryptor.generateSecretKey(JCCryptoAlgorithm.AES,JCCryptoConstants.BIT256);
			break;
		}
		return key;
	}

	/*
	 * Used to encrypt data by providing key in hex format. Gives output in base64 encoding.
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#encrypt(com.jamcracker.common.security.crypto.JCCryptoType, java.lang.String, java.lang.String)
	 */
	@Override
	public String encrypt(final JCCryptoType cryptoType, final String data, final String key)
			throws JCCryptoException, InvalidKeyException {
		String enc = new String();
		switch (cryptoType) {
		case CREDIT_CARD:
			enc = cryptor.encrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		case PERSONAL_DATA:
			enc = cryptor.encrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		case SERVICE_PASSWORD:
			enc = cryptor.encrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		case URL:
			enc = cryptor.encrypt(JCCryptoAlgorithm.AES,key,data);
			break;	
		default:
			enc = cryptor.encrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		}
		return enc;
	}
	
	/*
	 * Used to decrypt clear text by supplying key in hex format
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#decrypt(com.jamcracker.common.security.crypto.JCCryptoType, java.lang.String, java.lang.String)
	 */
	@Override
	public String decrypt(final JCCryptoType cryptoType, final String data, final String key)
			throws JCCryptoException, InvalidKeyException {
		String dec = new String();
		switch (cryptoType) {
		case CREDIT_CARD:
			dec = cryptor.decrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		case PERSONAL_DATA:
			dec = cryptor.decrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		case SERVICE_PASSWORD:
			dec = cryptor.decrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		case URL:
			dec = cryptor.decrypt(JCCryptoAlgorithm.AES,key,data);
			break;	
		default:
			dec = cryptor.decrypt(JCCryptoAlgorithm.AES,key,data);
			break;
		}
		return dec;
	}

	/*
	 * Used to generate a hash in base64 encoding format
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#generateHash(com.jamcracker.common.security.crypto.JCCryptoType, java.lang.String)
	 */
	@Override
	public String generateHash(final JCCryptoType cryptoType, final String toBeHashed)
			throws JCCryptoException {
		String hash=new String();
		switch (cryptoType) {
		case SDP:
			hash = cryptor.generateHash(JCCryptoAlgorithm.MD5, toBeHashed);
			break;
		default:
			hash = cryptor.generateHash(JCCryptoAlgorithm.MD5, toBeHashed);
			break;
		}
		return hash;
	}
	
	/*
	 * Used to generate one time pin
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#generateOneTimePin(java.lang.Long[])
	 */
	public String generateOneTimePin(Long entropy[]) throws JCCryptoException {
		return cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy, JCCryptoConstants.ONE_TIME_PIN_LENGTH);
	}
	
	
	/*
	 * Used to generate a hash for given algorithm
	 * @see com.jamcracker.common.security.crypto.ICryptoAPI#generateHash(com.jamcracker.common.security.crypto.JCCryptoType, java.lang.String)
	 */
	@Override
	public String generateHash(final JCCryptoAlgorithm algorithm, final String toBeHashed)
			throws JCCryptoException {
		return  cryptor.generateHash(algorithm, toBeHashed);
		
	}

	
	
}
