/*
 * 
 * Class: ICryptor.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Sep 07, 2013   kkpushparaj		1.0			Interface to hold core cryptographic operations
 * 2.0  Apr 4, 2014   Muthusamy		7.1			Included additional capability enc,dec,hash,compare based on given provider
 * 3.0  Jun 7, 2014   Muthusamy		7.1			Included additional capability for signature,verification,token
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 *****************************************************
 */
package com.jamcracker.common.security.crypto.core;

import java.security.InvalidKeyException;
import java.security.Key;

import com.jamcracker.common.security.crypto.JCDataLabel;
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
	 * 
	 * @param algorithm
	 * @param salt
	 * @param hash
	 * @return
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String generateHMAC(JCCryptoAlgorithm algorithm,String salt, String hash) throws JCCryptoException, InvalidKeyException;

	/**
	 * Responsible to generate keyed HMAC strings in bas64 encoded format
	 * @param algorithm
	 * @param salt
	 * @param hash
	 * @return base 64 encoded salt
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String generateHMAC(JCCryptoAlgorithm algorithm,Key salt, String hash) throws JCCryptoException, InvalidKeyException;
	
  	

	/**
	 * Used to generate a one time pin
	 * @param algorithm
	 * @param entropy
	 * @param size 
	 * @throws JCCryptoException
	 */
	public String generateOneTimePin(JCCryptoAlgorithm algorithm,Long entropy[],int size) throws JCCryptoException;
	
	/**
	 * Responsible for encryption 
	 * @param dataLabel
	 * @param algorithm
	 * @param key
	 * @param data
	 * @param provider
	 * @return
	 * @throws JCCryptoException
	 */
	public String encrypt(JCDataLabel dataLabel,String algorithm,final Key key, final String data,String provider) throws JCCryptoException;

	/**
	 * Responsible for de-cryption
	 * @param algorithm
	 * @param key
	 * @param data
	 * @param provider
	 * @return
	 * @throws JCCryptoException
	 */
	public String decrypt(String algorithm,final Key key, final String data,String provider) throws JCCryptoException;
	
	/**
	 * Responsible for decrypting key with passphrase
	 * @param protectedPassPhrase
	 * @param passPhrase
	 * @return
	 * @throws JCCryptoException
	 */
	public String decPassPhraseKey(Key protectedPassPhrase,String passPhrase) throws JCCryptoException;
	
	/**
	 * Responsible for encrypting data with passphrase
	 * @param data
	 * @param passPhrase
	 * @return
	 * @throws JCCryptoException
	 */
	public String encryptWithPassPhrase(String data,String passPhrase) throws JCCryptoException;

	/**
	 * Responsible for decrypting data with passphrase
	 * @param data
	 * @param passPhrase
	 * @return
	 * @throws JCCryptoException
	 */
	public String decryptWithPassPhrase(String data,String passPhrase) throws JCCryptoException;
	
	/**
	 * Responsible for Generating digital signature on data
	 * @param signedData
	 * @param originalData
	 * @param keyStoreType
	 * @param keyStoreProvider
	 * @param keyStoreFilePath
	 * @param sigAlgName
	 * @param aliasName
	 * @param storePassword
	 * @return
	 * @throws JCCryptoException
	 */
	
	public String generateDigitalSignature(String dataTosign,String keyStoreType,String keyStoreProvider,String keyStoreFilePath,
			String sigAlgName,String aliasName,String storePassword,String pvtKeyPassword) throws JCCryptoException ;
	/**
	 * Responsible for verifying digital signature on data
	 * @param signedData
	 * @param originalData
	 * @param keyStoreType
	 * @param keyStoreProvider
	 * @param keyStoreFilePath
	 * @param sigAlgName
	 * @param aliasName
	 * @param storePasswd
	 * @return true/false
	 * @throws JCCryptoException
	 */
	public boolean verifyDigitalSignature(String signedData,String originalData,String keyStoreType,String keyStoreProvider,
			String keyStoreFilePath,String sigAlgName,String aliasName,String storePasswd) throws JCCryptoException ;

	/**
	 * Responsible for verifying signature based on certificate File
	 * @param certificateFilePath
	 * @param originalData
	 * @param signedData
	 * @param sigAlgName
	 * @return true/false
	 * @throws JCCryptoException
	 */
	public boolean verifySignatureFromCertificate(String certificateFilePath, String originalData,String signedData ,String sigAlgName)
			throws JCCryptoException ;


}