/*
 * 
 * Class: CryptoService.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Apr 11, 2014   Muthusamy		7.0			Initial version.Interface for Cryptographic Operations
 * 2.0  Jun 7, 2014   Muthusamy		7.0			Included additional capability for signature,verification,token
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
package com.jamcracker.common.security.crypto;

import java.security.InvalidKeyException;

import com.jamcracker.common.security.crypto.core.JCCryptoAlgorithm;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.keymgmt.dto.KeyMetadata;

/**
 * High level interface to perform cryptographic operations. Key Generation will
 * be part of KMF Tool,hence jsdn CryptoService wont have method for generating
 * keys
 * 
 * @author marumugam
 * 
 */
public interface CryptoService {

	/**
	 * Method Used to encrypt data by providing dataLabel,data and actorId
	 * @param dataLabel
	 * @param data
	 * @param actorId
	 * @return encrypted Data
	 * @throws JCCryptoException
	 */
	public String encrypt(JCDataLabel dataLabel, String data, Integer actorId) throws JCCryptoException;

	/**
	 * Method Used to decrypt clear text by providing dataLabel,encData and actorId
	 * @param dataLabel
	 * @param data
	 * @param actorId
	 * @return actualData
	 * @throws JCCryptoException
	 */
	public String decrypt(JCDataLabel dataLabel, String data, Integer actorId) throws JCCryptoException;

	/**
	 * Method Used to generate HMAC by providing dataLabel,datatobehashed,actorId
	 * @param cryptoType
	 * @param hash
	 * @param actorId
	 * @return hashedData
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public String doHMAC(JCDataLabel cryptoType, String hash, Integer actorId) throws JCCryptoException, InvalidKeyException;

	/**
	 * Method Used to compare hashed password based on dataLabel and hashedData,existinghashedData,actorId
	 * @param dataLabel
	 * @param hash
	 * @param existingPassword
	 * @param actorId
	 * @return true/false
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	public boolean compareHMAC(JCDataLabel dataLabel, String hash, String existingPassword, Integer actorId) throws JCCryptoException, InvalidKeyException;
	
	/**
	 * Method used to generateHash based on alg,dataTobeHashed,KeyMetadata
	 * @param algorithm
	 * @param dataTohash
	 * @param permissionMetadata
	 * @return hashedData
	 * @throws JCCryptoException
	 */
	public String generateHash(final JCCryptoAlgorithm algorithm,final String dataTohash,KeyMetadata permissionMetadata) throws JCCryptoException ;

	/**
	 * Method Used to Generates Signature for given input
	 * @param dataTosign
	 * @param keyStoreType
	 * @param keyStoreProvider
	 * @param keyStoreFilePath
	 * @param sigAlgName
	 * @param aliasName
	 * @param storePasswd
	 * @param pvtKeyPassword
	 * @param permissionMetadata
	 * @return Signature in string format
	 * @throws JCCryptoException
	 */
	public String generateDigitalSignature(String dataTosign,String keyStoreType,String keyStoreProvider,String keyStoreFilePath,
			String sigAlgName,String aliasName,String storePasswd,String pvtKeyPassword,KeyMetadata permissionMetadata) throws JCCryptoException ;
	
	/**
	 * Method Used to Verify Signature for based on signedData and OriginalData
	 * @param signedData
	 * @param originalData
	 * @param keyStoreType
	 * @param keyStoreProvider
	 * @param keyStoreFilePath
	 * @param sigAlgName
	 * @param aliasName
	 * @param storePasswd
	 * @param permissionMetadata
	 * @return true/false
	 * @throws JCCryptoException
	 */
	public boolean verifyDigitalSignature(String signedData,String originalData,String keyStoreType,String keyStoreProvider,
			String keyStoreFilePath,String sigAlgName,String aliasName,String storePasswd,KeyMetadata permissionMetadata) throws JCCryptoException ;

	/**
	 * Method Used to Generates a Random Token
	 * @param permissionMetadata
	 * @return token as String
	 * @throws JCCryptoException
	 */
	public String generateToken(KeyMetadata permissionMetadata) throws JCCryptoException ;

	/**
	 * Method Used to encrypt data using given passphrase
	 * @param passPhrase
	 * @param data
	 * @param permissionMetadata
	 * @return encryptedData
	 * @throws JCCryptoException
	 */
	public String encryptWithPassPhrase(String passPhrase,String data,KeyMetadata permissionMetadata) throws JCCryptoException ;

	/**
	 * Method Used to decrypt data using given passphrase    
	 * @param passPhrase
	 * @param data
	 * @param permissionMetadata
	 * @return decryptedData
	 * @throws JCCryptoException
	 */
	public String decryptWithPassPhrase(String passPhrase,String data,KeyMetadata permissionMetadata) throws JCCryptoException ;


}
