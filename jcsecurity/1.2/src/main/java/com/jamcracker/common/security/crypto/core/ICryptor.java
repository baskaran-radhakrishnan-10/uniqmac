package com.jamcracker.common.security.crypto.core;

import java.security.InvalidKeyException;

import com.jamcracker.common.security.crypto.exception.JCCryptoException;

/**
 * Interface to hold core cryptographic operations
 * @author kkpushparaj
 *
 */
public interface ICryptor {
	/**
	 * Generates secret key by providing an algorithm and bit size
	 * @param algorithm
	 * @param bit
	 * @return key in Hex format
	 * @throws JCCryptoException
	 */
	public String generateSecretKey(JCCryptoAlgorithm algorithm,int bit) throws JCCryptoException;

	/**
	 * Responsible for encryption
	 * @param algorithm
	 * @param key
	 * @param data
	 * @return base64 encoded 
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String encrypt(JCCryptoAlgorithm algorithm, String key, String data)	throws JCCryptoException, InvalidKeyException;

	/**
	 * Responsible for de-cryption
	 * @param algorithm
	 * @param key
	 * @param data
	 * @return plain text
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String decrypt(JCCryptoAlgorithm algorithm, String key, String data)throws JCCryptoException, InvalidKeyException;

	/**
	 * Generates salt
	 * @param algorithm
	 * @param size
	 * @return salt in base64 format
	 * @throws JCCryptoException
	 */
	public String generateSalt(JCCryptoAlgorithm algorithm,int size) throws JCCryptoException;

	/**
	 * Generates Hash
	 * @param algorithm
	 * @param hash
	 * @return has in bas 64 encoded format
	 * @throws JCCryptoException
	 */
	public String generateHash(JCCryptoAlgorithm algorithm,String hash) throws JCCryptoException;

	/**
	 * Responsible to generate keyed HMAC strings in bas64 encoded format
	 * @param algorithm
	 * @param salt
	 * @param hash
	 * @return base 64 encoded salt
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String generateHMAC(JCCryptoAlgorithm algorithm,String salt, String hash) throws JCCryptoException, InvalidKeyException;

	/**
	 * Used to generate a one time pin
	 * @param algorithm
	 * @param entropy
	 * @param size 
	 * @throws JCCryptoException
	 */
	public String generateOneTimePin(JCCryptoAlgorithm algorithm,Long entropy[],int size) throws JCCryptoException;


}