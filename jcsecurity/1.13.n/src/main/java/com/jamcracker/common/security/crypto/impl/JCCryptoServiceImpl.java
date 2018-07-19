/*
 * 
 * Class: JCCryptoServiceImpl.java
 *
 *
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
package com.jamcracker.common.security.crypto.impl;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.crypto.CryptoService;
import com.jamcracker.common.security.crypto.IKMFCryptoConstantsMapper;
import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.crypto.core.ICryptor;
import com.jamcracker.common.security.crypto.core.JCCryptoAlgorithm;
import com.jamcracker.common.security.crypto.exception.DecryptionFailedException;
import com.jamcracker.common.security.crypto.exception.EncryptionFailedException;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.exception.JCCryptoFaultCode;
import com.jamcracker.common.security.crypto.metadata.CryptoAttribute;
import com.jamcracker.common.security.keymgmt.dto.KeyMetadata;
import com.jamcracker.common.security.keymgmt.service.KeyManagementService;
import com.jamcracker.common.security.keymgmt.service.KmfMgmtCache;
/**
 * Implementation class for High level cryptographic operations
 * 
 * @author marumugam
 * 
 */
public class JCCryptoServiceImpl implements CryptoService,IKMFCryptoConstantsMapper {

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(JCCryptoServiceImpl.class.getName());

	private ICryptor cryptor;
	private KeyManagementService keyManagerService;
	private boolean cryptoMode;

	
	/**
	 * This methods returns the ICryptor implementation (JCCryptor) object
	 * reference.
	 */
	public ICryptor getCryptor() {
		return cryptor;
	}

	/**
	 * This methods sets the ICryptor implementation object reference while
	 * initiating JCCryptoServiceImpl bean in jccrypto-context.xml
	 * 
	 * @param cryptor
	 */
	public void setCryptor(ICryptor cryptor) {
		this.cryptor = cryptor;
	}

	/**
	 * This methods returns the KeyManagementService implementation
	 * (KeyManagementServiceImpl) object reference.
	 */
	public KeyManagementService getkeyManagerService() {
		return keyManagerService;
	}

	public void setkeyManagerService(KeyManagementService keyManagerAPI) {
		this.keyManagerService = keyManagerAPI;
	}
	
	/**
	 * Used to encrypt data by providing dataLabel,data,actorId. Gives
	 * output in base64 encoding along with Crytography KMF metadata .example
	 * 1-1001-2001-3001-8001-5004~encodeddata[LATESTVESION-KEY_TYPE-ALGORITHM-
	 * KEY_LENGTH-KEY_ID-DATA_LABELS]
	 * @param dataLabel
	 * @param data
	 * @param actorId
	 * @return encrypted Data
	 * @throws JCCryptoException 
	 */
	@Override
	public String encrypt(JCDataLabel dataLabel, String data, Integer actorId) throws EncryptionFailedException
	{
		String enc = new String();
		CryptoAttribute cryptoAttribute=null;
		
		try {
			cryptoAttribute = keyManagerService.getCryptoAttribute(dataLabel, actorId, getDataLabelVersion(dataLabel),cryptoMode);
		  } catch (JCCryptoException e) {
			  throw new EncryptionFailedException(JCCryptoFaultCode.CRYPTO_ENC_FAILURE);
		   }
		
		 if(cryptoAttribute.getStatus()==JCSecurityConstants.KEY_STATUS_EXPIRED)
				throw new EncryptionFailedException(JCCryptoFaultCode.CRYPTO_KEY_EXPIRED);
		
	    try 
	    {
 		 enc = cryptor.encrypt(dataLabel, cryptoAttribute.getAlgorithm(), cryptoAttribute.getKey(), data, cryptoAttribute.getProvider());
		}catch (JCCryptoException e) {
			throw new EncryptionFailedException(JCCryptoFaultCode.CRYPTO_ENC_FAILURE);
		}
		
	  return enc;
	}

	/**
	 * Used to decrypt clear text by supplying data in hex format. Encrypted
	 * data will be in the form of  1-1001-2001-3001-8001-5004~encrypteddata
	 * [LATESTVESION-KEY_TYPE-ALGORITHM-KEY_LENGTH-KEY_ID-DATA_LABELS]
	 * seperate datatoEncrypt and load respective version of key attributes
	 * from keyManagerService and call  decrypt
	 * @param dataLabel
	 * @param data
	 * @param actorId
	 * @return actualData
	 * @throws JCCryptoException
	 */

	@Override
	public String decrypt(JCDataLabel dataLabel, String data, Integer actorId) throws DecryptionFailedException {
		String dec = new String();
		String actualDataToDecrypt = null;
		String actualDataVersion = null;
		cryptoMode = true;
		if (data.contains(JCSecurityConstants.CMX_SEPERATOR)) {
			actualDataVersion = data.substring(0, data.indexOf(JCSecurityConstants.CMX_METADATA_SEPERATOR));
			int index = data.indexOf(JCSecurityConstants.CMX_SEPERATOR);
			actualDataToDecrypt = data.substring(index + 1, data.length());
		} else {
			actualDataToDecrypt = data;
		}
		
		CryptoAttribute cryptoAttribute=null;
		try {
			cryptoAttribute = keyManagerService.getCryptoAttribute(dataLabel, actorId, actualDataVersion,cryptoMode);
			dec = cryptor.decrypt(cryptoAttribute.getAlgorithm(), cryptoAttribute.getKey(), actualDataToDecrypt, cryptoAttribute.getProvider());
		} catch (JCCryptoException e) {
			throw new DecryptionFailedException(JCCryptoFaultCode.CRYPTO_DEC_FAILURE);
		}
		return dec;
	
	}

	/**
	 * Returns Latest version for DataLabel
	 * @param dataLabel
	 * @return dataLabelVersion
	 */
	
	private String getDataLabelVersion(JCDataLabel dataLabel) throws JCCryptoException{
		KmfMgmtCache kmfCache= KmfMgmtCache.getInstance().getlatestVersion(dataLabel);
		int dataLabelVersion = kmfCache.getLatestVersion();
		return Integer.toString(dataLabelVersion);
	}
	
	/**
	 * Used to generate a HMAC by providing dataLabel,datatobehashed,actorId. Gives in base64 format.
	 * Hashed  data will be in the form of  1-1001~hashed[VERSION-KEY_TYPE-ALGORITHM]
	 * @param cryptoType
	 * @param hash
	 * @param actorId
	 * @return hashedData
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */

	@Override
	public String doHMAC(JCDataLabel dataLabel, final String toBeHashed, Integer actorId) throws JCCryptoException, InvalidKeyException {
		LOGGER.debug("doHMAC Starts for " + dataLabel.getName());
		String hash = new String();
		CryptoAttribute cryptoAttribute = keyManagerService.getCryptoAttribute(dataLabel, actorId, getDataLabelVersion(JCDataLabel.HPROTECTOR),cryptoMode);
		hash = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, cryptoAttribute.getKey(), toBeHashed);
		KmfMgmtCache kmfCache= KmfMgmtCache.getInstance().getcmxDataMap(dataLabel);
		String cmxData = kmfCache.getCmxData() + JCSecurityConstants.CMX_SEPERATOR;
		LOGGER.debug("doHMAC Ends for " + dataLabel.getName());
		return cmxData + hash;
	}

	/**
	 * Used to compare hashed password by providing dataLabel and datatobehashed,existinghashedpassword.
	 * Hashed  data will be in the form of  1-1001~hashed[VERSION-KEY_TYPE-ALGORITHM].
	 * seperate datatobehashed and load respective version of key attributes
	 * from keyManagerService and call  generateHMAC,do comparison
 	 * @param dataLabel
	 * @param hash
	 * @param existingPassword
	 * @param actorId
	 * @return true/false
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	@Override
	public boolean compareHMAC(JCDataLabel dataLabel, String toBeHashed, String dbPassword, Integer actorId) throws JCCryptoException, InvalidKeyException {
		String actualDbDataToHash = null;
		boolean validPassword = false;
		String hash = new String();
		if (dbPassword.contains(JCSecurityConstants.CMX_SEPERATOR)) {
			int index = dbPassword.indexOf(JCSecurityConstants.CMX_SEPERATOR);
			actualDbDataToHash = dbPassword.substring(index + 1, dbPassword.length());
		}else{
			actualDbDataToHash = dbPassword;
		}
		CryptoAttribute cryptoAttribute = keyManagerService.getCryptoAttribute(dataLabel, actorId, getDataLabelVersion(JCDataLabel.HPROTECTOR),cryptoMode);
		hash = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, cryptoAttribute.getKey(), toBeHashed);
		if (actualDbDataToHash.equals(hash)) {
			validPassword = true;
		}
		return validPassword;
	}

	/**
	 * Generate Hash
	 * @param algorithm
	 * @param dataTohash
	 * @param permissionMetadata
	 * @return hashedData
	 * @throws JCCryptoException
	 */
	@Override
	public String generateHash(JCCryptoAlgorithm algorithm, String dataTohash,
			KeyMetadata permissionMetadata) throws JCCryptoException {
		String hashedData = null;
		if(permissionMetadata!=null && permissionMetadata.getLabels()!=null && 
				permissionMetadata.getLabels().getCryptoCapability().equalsIgnoreCase(IKMFCryptoConstantsMapper.OPERATION_HMAC)){
			hashedData=cryptor.generateHash(algorithm, dataTohash);
		}else{
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INTERNAL_ERROR);
		}
		return hashedData;
	}

	/**
	 * Used To Generate Digital Signature
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
	@Override
	public String generateDigitalSignature(String dataTosign,String keyStoreType,String keyStoreProvider,String keyStoreFilePath,
			String sigAlgName, String aliasName, String storePasswd,String pvtKeyPassword, KeyMetadata permissionMetadata)
			throws JCCryptoException {
		String generatedSignature = null;
		if(permissionMetadata!=null && permissionMetadata.getLabels()!=null && 
				permissionMetadata.getLabels().getCryptoCapability().equalsIgnoreCase(IKMFCryptoConstantsMapper.OPERATION_DIGITAL_SIGN)){
			generatedSignature = cryptor.generateDigitalSignature(dataTosign, keyStoreType, keyStoreProvider, keyStoreFilePath, sigAlgName, aliasName, storePasswd, pvtKeyPassword);
		}else{
			LOGGER.error("Error Occurred Permission Metadata is null : generateDigitalSignature");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INTERNAL_ERROR);
		}
		return generatedSignature;
	}

	/**
	 * Used To Verify Digital Signature
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
	@Override
	public boolean verifyDigitalSignature(String signedData,String originalData,String keyStoreType,String keyStoreProvider,
			String keyStoreFilePath,final String sigAlgName,String aliasName,String storePasswd,KeyMetadata permissionMetadata) 
					throws JCCryptoException {
		boolean signatureVerifyResult = false;
		if(permissionMetadata!=null && permissionMetadata.getLabels()!=null && 
				permissionMetadata.getLabels().getCryptoCapability().equalsIgnoreCase(IKMFCryptoConstantsMapper.OPERATION_DIGITAL_SIGN_VERIFY)){
			signatureVerifyResult = cryptor.verifyDigitalSignature(signedData, originalData, keyStoreType, keyStoreProvider,
					keyStoreFilePath, sigAlgName, aliasName, storePasswd);
		}else{
			LOGGER.error("KMF : Error Occurred Permission Metadata is null : verifyDigitalSignature");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INTERNAL_ERROR);
		}
		return signatureVerifyResult;

	}

	/**
	 * Method Used to Generates a Random Token
	 * @param permissionMetadata
	 * @return token as String
	 * @throws JCCryptoException
	 */
	@Override
	public String generateToken(KeyMetadata permissionMetadata) throws JCCryptoException {
		try {
			if(permissionMetadata!=null && permissionMetadata.getLabels()!=null 
					&& permissionMetadata.getLabels().getCryptoCapability().equals(IKMFCryptoConstantsMapper.OPERATION_TOKEN)) {
			byte[] filledRandomBytes = new byte[512];
			Integer a=(int) (System.nanoTime() * 99999);
			byte[] junkBytes=new String(a.toString()).getBytes();
			SecureRandom prng = SecureRandom.getInstance(JCCryptoAlgorithm.SHA1_PRNG.algorithmName());
			prng.setSeed(filledRandomBytes.length*999999999*System.nanoTime());
			prng.nextBytes(filledRandomBytes);
			MessageDigest sha = MessageDigest.getInstance("SHA-512");
			sha.update(junkBytes);
			sha.update(filledRandomBytes);
			return new sun.misc.BASE64Encoder().encode(sha.digest());
			}else{
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INTERNAL_ERROR);	
			}
		} catch (NoSuchAlgorithmException nsae) {
			LOGGER.error("KMF: generateToken ");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM,nsae);
		}
	}
	
	/**
	 * Method Used to encrypt data using given passphrase
	 * @param passPhrase
	 * @param data
	 * @param permissionMetadata
	 * @return encryptedData
	 * @throws JCCryptoException
	 */
	@Override
	public String encryptWithPassPhrase(String passPhrase, String data,KeyMetadata permissionMetadata) throws JCCryptoException {
		String encypytedWithPassphrase=null;
		if(permissionMetadata!=null && KmfMgmtCache.validateCaller()){
			encypytedWithPassphrase =cryptor.encryptWithPassPhrase(data, passPhrase); 
		}else{
			LOGGER.error("Error Occurred Permission Metadata is null : encryptWithPassPhrase");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INTERNAL_ERROR);
		}
		return encypytedWithPassphrase;
	}

	/**
	 * Method Used to decrypt data using given passphrase    
	 * @param passPhrase
	 * @param data
	 * @param permissionMetadata
	 * @return decryptedData
	 * @throws JCCryptoException
	 */
	@Override
	public String decryptWithPassPhrase(String passPhrase, String data,KeyMetadata permissionMetadata) throws JCCryptoException {
		String decypytedWithPassphrase=null;
		if(permissionMetadata!=null && KmfMgmtCache.validateCaller()){
			decypytedWithPassphrase = cryptor.decryptWithPassPhrase(data, passPhrase);;
		}else{
			LOGGER.error("Error Occurred Permission Metadata is null : decryptWithPassPhrase");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INTERNAL_ERROR);
		}
		return decypytedWithPassphrase;
	}
	
	

}
