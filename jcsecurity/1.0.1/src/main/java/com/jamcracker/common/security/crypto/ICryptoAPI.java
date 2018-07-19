package com.jamcracker.common.security.crypto;

import java.security.InvalidKeyException;

import com.jamcracker.common.security.crypto.core.JCCryptoAlgorithm;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;

/**
 * High level interface to perform cryptographic operations 
 * @author kkpushparaj
 *
 */
public interface ICryptoAPI {
	/**
	 * Used to generate the salt in given size
	 * @param cryptoType
	 * @return salt in base64 format
	 * @throws JCCryptoException
	 */
	public String generateSalt(JCCryptoType cryptoType) throws JCCryptoException;

	/**
	 * Used to generate a HMAC by providing salt. Gives in base64 format.
	 * @param cryptoType
	 * @param salt
	 * @param hash
	 * @return HMAC in base64 format
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String generateHMAC(JCCryptoType cryptoType,String salt, String hash) throws JCCryptoException, InvalidKeyException;

	/**
	 * Used to generate cryptographic keys in hex format
	 * @param cryptoType
	 * @return key in hex format
	 * @throws JCCryptoException
	 */
	public String generateKey(JCCryptoType cryptoType) throws JCCryptoException;

	/**
	 * Used to encrypt data by providing key in hex format. Gives output in base64 encoding.
	 * @param cryptoType
	 * @param data
	 * @param key
	 * @return bas64 encoded encrypted text
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String encrypt(JCCryptoType cryptoType,String data, String key) throws JCCryptoException,InvalidKeyException;

	/**
	 * Used to decrypt clear text by supplying key in hex format
	 * @param cryptoType
	 * @param data
	 * @param key
	 * @return clear decryptde text
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String decrypt(JCCryptoType cryptoType,String data, String key) throws JCCryptoException,InvalidKeyException;

	/**
	 * Used to generate a hash in base64 encoding format
	 * @param cryptoType
	 * @param hash
	 * @return hash in hex format
	 * @throws JCCryptoException
	 */
	public String generateHash(JCCryptoType cryptoType,String hash) throws JCCryptoException;

	/**
	 * Used to generate a one time pin
	 * @param entropy
	 * @throws JCCryptoException
	 */
	public String generateOneTimePin(Long entropy[]) throws JCCryptoException;
	
	
	/**
	 * generateHash based on  JCCryptoAlgorithm
	 * @param algorithm
	 * @param toBeHashed
	 * @return
	 */
	public String generateHash(final JCCryptoAlgorithm algorithm, final String toBeHashed) throws JCCryptoException;
}
