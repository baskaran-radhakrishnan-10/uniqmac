/*
 * 
 * Class: JCCryptor.java
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
package com.jamcracker.common.security.crypto.core;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import com.jamcracker.common.exception.JCFaultCode;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.crypto.exception.DecryptionFailedException;
import com.jamcracker.common.security.crypto.exception.EncryptionFailedException;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.exception.JCCryptoFaultCode;
import com.jamcracker.common.security.keymgmt.service.KmfMgmtCache;

/**
 * Responsible for cryptographic operations extends core class
 * @author kkpushparaj
 *
 */
public class JCCryptor extends JCCryptorBase implements ICryptor {
	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(JCCryptor.class.getName());
	private final JCHex hex = new JCHex();
	


	
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
	@Override
	public String generateHMAC(final JCCryptoAlgorithm algorithm,final String salt, final String hash)
			throws JCCryptoException, InvalidKeyException {
		
		return doHMac(algorithm,salt,hash);
	}

	//Generates HMAC string in base64 format by supplying algorithm and SALT
	@Override
	public String generateHMAC(final JCCryptoAlgorithm algorithm,final Key salt, final String hash)
			throws JCCryptoException, InvalidKeyException {
		
		return doHMac(algorithm,salt,hash);
	}


	//generates one time pin
//	@Override
	
	public String generateOneTimePin(JCCryptoAlgorithm algorithm,
			Long[] entropy, int size) throws JCCryptoException {
		
		final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
			 
//		setAlgorithm(algorithm);
		String salt = generateSalt(JCCryptoAlgorithm.HMACSHA1, JCCryptoConstants.SALTSIZE1);
		
		long t0 = 0;
        long x = 30;
        long time = System.currentTimeMillis();
 
        String steps = "0";
 		
		long t = (time - t0) / x;
        steps = Long.toHexString(t).toUpperCase();
 
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
	/**
	 * Responsible for encryption 
	 * @param dataLabel
	 * @param algorithm
	 * @param key
	 * @param data
	 * @param provider
	 * @return encrypted Data along with CMX info
	 * @throws JCCryptoException
	 */

	@Override
	public String encrypt(JCDataLabel dataLabel,String algorithm, Key key, String data,String provider) throws EncryptionFailedException,JCCryptoException {
		byte[] cipherBytes = data.getBytes();
		byte[] encdata = null;
		try {
			encdata = doCrypt(algorithm, key, cipherBytes, CRYTO_MODE.ENCRYPT,provider);
		} catch (JCCryptoException e) {
			LOGGER.error("KMF: encrypt failure");
			throw new EncryptionFailedException(JCCryptoFaultCode.CRYPTO_ENC_FAILURE);
		}
		KmfMgmtCache kmfCache= KmfMgmtCache.getInstance().getcmxDataMap(dataLabel);
		String cmxData =   kmfCache.getCmxData() + JCSecurityConstants.CMX_SEPERATOR ;
		String encryptedData=cmxData + new String(Base64.encodeBase64(encdata));
		return encryptedData;
	}

	/**
	 * Responsible for decryption
	 * @param algorithm
	 * @param key
	 * @param data
	 * @param provider
	 * @return actualdata
	 * @throws JCCryptoException
	 */
	@Override
	public String decrypt(String algorithm, Key key, String data,String provider)throws DecryptionFailedException {
		
		byte[] cipherBytes = Base64.decodeBase64(data.getBytes());
		String decryptedData = "";
		try
		{
			decryptedData = new String(doCrypt(algorithm, key, cipherBytes, CRYTO_MODE.DECRYPT,provider)); 	
		}catch(JCCryptoException e) {
			LOGGER.error("KMF: decrypt failure");
			throw new DecryptionFailedException(JCCryptoFaultCode.CRYPTO_DEC_FAILURE);
		}
	  return decryptedData; 
	}
	
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
	 * @return signed-data as String with Base64 encoded
	 * @throws JCCryptoException
	 */

	@Override
	public String generateDigitalSignature(String dataTosign,String keyStoreType, String keyStoreProvider,String keyStoreFilePath,
			String sigAlgName, String aliasName,String storePassword, String pvtKeyPassword) throws JCCryptoException {
		byte[] signatureBytes = null, dataToBeSignedBytes = null;
		Signature signature = null;
		try {
			KeyStore keyStore=loadKeyStore(keyStoreType, keyStoreProvider, keyStoreFilePath, storePassword.toCharArray());
			signature = Signature.getInstance(sigAlgName);
			PrivateKey privatekey = loadPrivateKey(keyStore,aliasName, pvtKeyPassword.toCharArray());
			signature.initSign(privatekey);
			dataToBeSignedBytes = dataTosign.getBytes("UTF8");
			signature.update(dataToBeSignedBytes);
			signatureBytes = signature.sign();
		} catch (InvalidKeyException e) {
			LOGGER.error("KMF: generateDigitalSignature : InvalidKeyException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY,e);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("KMF: generateDigitalSignature : NoSuchAlgorithmException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM,e);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("KMF: generateDigitalSignature : UnsupportedEncodingException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_UNSUPPORTED_ENCODING,e);
		} catch (SignatureException e) {
			LOGGER.error("KMF: generateDigitalSignature : SignatureException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_SIGNATURE_EXCEPTION,e);
		}
		return com.sun.identity.shared.encode.Base64.encode(signatureBytes);
	}

	
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
	
	@Override
	public boolean verifyDigitalSignature(String signedData,String originalData, String keyStoreType, String keyStoreProvider,
			String keyStoreFilePath, String sigAlgName, String aliasName,String storePasswd) throws JCCryptoException {
		byte[] signedDataBytes = null, originalDataBytes = null;
		boolean signatureVerifyResult = false;
		Signature signature = null;
		try {
			KeyStore keyStore=loadKeyStore(keyStoreType, keyStoreProvider, keyStoreFilePath, storePasswd.toCharArray());
			signature = Signature.getInstance(sigAlgName);
			java.security.cert.Certificate loadedCertificate = loadCertificateFromKeyStore(keyStore,aliasName);
			signature.initVerify(loadedCertificate.getPublicKey());
			signedDataBytes = com.sun.identity.shared.encode.Base64.decode(signedData);
			originalDataBytes = originalData.getBytes("UTF8");
			signature.update(originalDataBytes);
			signatureVerifyResult = signature.verify(signedDataBytes);
		} catch (InvalidKeyException e) {
			LOGGER.error("KMF: verifyDigitalSignature : UnsupportedEncodingException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY,e);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("KMF: verifyDigitalSignature : NoSuchAlgorithmException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM,e);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("KMF: verifyDigitalSignature : UnsupportedEncodingException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_UNSUPPORTED_ENCODING,e);
		} catch (SignatureException e) {
			LOGGER.error("KMF: verifyDigitalSignature : SignatureException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_SIGNATURE_EXCEPTION,e);
		}
		return signatureVerifyResult;
	}
	
	
	/**
	 * Responsible for decrypting key with passphrase
	 * @param protectedPassPhrase
	 * @param passPhrase
	 * @return actualData
	 * @throws JCCryptoException
	 */
	@Override
	public String decPassPhraseKey(Key protectorKey,String passPhrase) throws JCCryptoException{
		final byte[] passPDec= decryptWithPassPhrase(protectorKey, passPhrase);
		String originalKey = new String(passPDec);
		return originalKey;
	}

	/**
	 * Responsible for encrypting data with passphrase
	 * @param protectedPassPhrase
	 * @param passPhrase
	 * @return
	 * @throws JCCryptoException
	 */
	public String encryptWithPassPhrase(String data,String passPhrase) throws JCCryptoException {
		final byte[] passPhraseValue = encryptDecryptWithPassPhrase(data.getBytes(), passPhrase, true);
		String passPhraseKey = new String(hex.encodeHex(passPhraseValue));
		return passPhraseKey;
	}

	/**
	 * Responsible for decrypting data with passphrase
	 * @param protectedPassPhrase
	 * @param passPhrase
	 * @return
	 * @throws JCCryptoException
	 */
	public String decryptWithPassPhrase(String data,String passPhrase) throws JCCryptoException {
		final byte[] passPhraseValue = encryptDecryptWithPassPhrase(hex.decodeHex(data), passPhrase, false);
		String originalValue = new String(passPhraseValue);
		return originalValue;
	}

	/**
	 * Responsible for verifying signature based on certificate File
	 * @param certificateFilePath
	 * @param originalData
	 * @param signedData
	 * @param sigAlgName
	 * @return true/false
	 * @throws JCCryptoException
	 */
	@Override
	public boolean verifySignatureFromCertificate(String certificateFilePath,String originalData, String signedData, String sigAlgName)
			throws JCCryptoException {
		byte[] signedDataBytes = null, originalDataBytes = null;
		boolean signatureVerifyResult = false;
		Signature signature = null;
			try {
				signature = Signature.getInstance(sigAlgName);
				signature.initVerify(CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certificateFilePath)));
				signedDataBytes = com.sun.identity.shared.encode.Base64.decode(signedData);;
				originalDataBytes = originalData.getBytes("UTF8");
				signature.update(originalDataBytes);
				signatureVerifyResult = signature.verify(signedDataBytes);
			} catch (InvalidKeyException e) {
				LOGGER.error("KMF: verifySignatureFromCertificate : InvalidKeyException"+certificateFilePath);
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY,e);
			} catch (NoSuchAlgorithmException e) {
				LOGGER.error("KMF: verifySignatureFromCertificate : NoSuchAlgorithmException"+sigAlgName);
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM,e);
			} catch (CertificateException e) {
				LOGGER.error("KMF: verifySignatureFromCertificate : CertificateException");
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_CERTIFICATE_EXCEPTION,e);
			} catch (FileNotFoundException e) {
				LOGGER.error("KMF: verifySignatureFromCertificate : FileNotFoundException"+certificateFilePath);
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_CERTIFICATE_EXCEPTION,e);
			} catch (UnsupportedEncodingException e) {
				LOGGER.error("KMF: verifySignatureFromCertificate : UnsupportedEncodingException");
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_UNSUPPORTED_ENCODING,e);
			} catch (SignatureException e) {
				LOGGER.error("KMF: verifySignatureFromCertificate : SignatureException");
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_SIGNATURE_EXCEPTION,e);
			}
			
		return signatureVerifyResult;
	}

}