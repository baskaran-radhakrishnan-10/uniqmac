/*
 * 
 * Class: JCCryptorBase.java
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
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.exception.JCFaultCode;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.exception.JCCryptoFaultCode;
import com.sun.identity.shared.encode.Base64;

/**
 * Core abstract class for cryptographic operations 
 * @author kkpushparaj
 *
 */

abstract class JCCryptorBase {
	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger	.getLogger(JCCryptorBase.class.getName());

	//Default initialization vector
	private final byte[] iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	private final IvParameterSpec ips = new IvParameterSpec(iv);
	private final JCHex hex = new JCHex();

	//Passphrase key properties needs to be initialized one time only to improve performance 
	private static String cipherPadding = JCProperties.getInstance().getProperty("jsdn.kmf.cipher.padding");
	private static Key passphraseKey=null;
	private static Cipher passphraseCipher=null;
	private static String salt = JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.salt");
	private static String keyAlg = JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.key.alg");
	private static String prov = JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.provider");
	private static String passphraseAlg = JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.key.passphrase.alg");
	private final int  iterationCount = Integer.parseInt(JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.iterationCount"));
	private final int  keyLength = Integer.parseInt(JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.keylength"));
	


	//Cryptographic modes
	protected enum CRYTO_MODE {
		ENCRYPT (Cipher.ENCRYPT_MODE), DECRYPT(Cipher.DECRYPT_MODE);
		CRYTO_MODE(Integer cipherMode) {
			this.cipherMode = cipherMode;
		}
		Integer cipherMode;
		/**
		 * @return the cipherMode
		 */
		protected Integer getCipherMode() {
			return cipherMode;
		}
		/**
		 * @param cipherMode the cipherMode to set
		 */
		protected void setCipherMode(Integer cipherMode) {
			this.cipherMode = cipherMode;
		}
		
	}

	/**
	 * doHMac is an overloaded method 
	 * @param algorilthm
	 * @param salt
	 * @param data
	 * @return
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	protected String doHMac(final JCCryptoAlgorithm algorithm, final String salt, final String data) throws JCCryptoException,InvalidKeyException {
		String hashedValue = null;
		try
		{
			Key secretKey = constructKey(salt, algorithm.algorithmName());
			hashedValue = doHMac(algorithm, secretKey, data);
		} catch (final JCCryptoException e) {
			LOGGER.error("KMF: doHMac : Issue in loading Hashing Algotithm : "	+ e.getLocalizedMessage());
			throw e;
		}
		return hashedValue;
	}
	
	 
	/**
	 * Responsible to perform HMAC 
	 * @param algorithm
	 * @param salt
	 * @param data
	 * @return
	 * @throws JCCryptoException
	 * @throws InvalidKeyException
	 */
	protected String doHMac(final JCCryptoAlgorithm algorithm, final Key salt, final String data) throws JCCryptoException,InvalidKeyException {
		Mac hMac = null;
		try {
			hMac = Mac.getInstance(algorithm.algorithmName());
			hMac.init(salt);
			hMac.update(data.getBytes());
		} catch (final NoSuchAlgorithmException e) {
			LOGGER.error("KMF : Issue in loading Hashing Algotithm : "+ algorithm.algorithmName()	+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		return Base64.encode(hMac.doFinal());
	}

	
	/**
	 * Responsible to perform HASHING 
	 * @param algorithm
	 * @param data
	 * @return
	 * @throws JCCryptoException
	 */
	
	protected byte[] doHash(final JCCryptoAlgorithm algorithm, final String data) throws JCCryptoException {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance(algorithm.algorithmName());
		} catch (final NoSuchAlgorithmException e) {
			LOGGER.error("KMF: Issue in loading HASHING Algotithm : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		md.update(data.getBytes());
		return md.digest();
	}

	
	/**
	 * Responsible to perform encrypt/decrypt
	 * @param algorithm
	 * @param key
	 * @param cipherBytes
	 * @param cryptoMode
	 * @return
	 * @throws JCCryptoException
	 */
	protected byte[] doCrypt(JCCryptoAlgorithm algorithm, String key, final byte[] cipherBytes, CRYTO_MODE cryptoMode)  throws JCCryptoException {
		Cipher ecipher=null;
		byte[] cryptedBytes = null;
		try {
			ecipher = Cipher.getInstance(algorithm.fullName());
		} catch (final NoSuchAlgorithmException e) {
			LOGGER.error("KMF: Issue in loading ENCRYPTION Algotithm : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM);
		} catch (final NoSuchPaddingException e) {
			LOGGER.error("KMF: Padding not supported : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PADDIING);
		}
		
		byte[] raw = hex.decodeHex(key);
		SecretKeySpec skeySpec= new SecretKeySpec(raw, algorithm.algorithmName());
		 
		try {
			ecipher.init(cryptoMode.getCipherMode(), skeySpec, ips);
		} catch (final InvalidKeyException e) {
			LOGGER.error("KMF: Supplied key is invalid : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY);
		} catch (final InvalidAlgorithmParameterException e) {
			LOGGER.error("KMF: Invalid IV : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_ALG_PARAM);
		}
		try {
			cryptedBytes = ecipher.doFinal(cipherBytes);
		} catch (final IllegalStateException e) { 
			LOGGER.error("KMF: Could not perform crypto operation : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_ILLEGAL_STATE);
		} catch (final IllegalBlockSizeException e) {
			LOGGER.error("KMF: Could not perform crypto operation : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_ILLEGAL_BLOCK_SIZE);
		} catch (final BadPaddingException e) {
			LOGGER.error("KMF: Could not perform crypto operation : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_BAD_PADDING);
		}
		
		return cryptedBytes;
	}
	
	/**
	 * Used to encrypt/decrypt data by providing alg,key,data,cipherMode,Provider
	 * @param algorithm
	 * @param key
	 * @param cipherBytes
	 * @param cryptoMode
	 * @param provider
	 * @return
	 * @throws JCCryptoException
	 */
	protected byte[] doCrypt(String algorithm, Key key, final byte[] cipherBytes, CRYTO_MODE cryptoMode,String provider)  throws JCCryptoException {
	
		 Cipher ecipher=null;
		 byte[] cryptedBytes = null;

		try{
			ecipher = Cipher.getInstance(algorithm +cipherPadding ,provider);
			IvParameterSpec ips = new IvParameterSpec(new byte[ecipher.getBlockSize()]);
			ecipher.init(cryptoMode.getCipherMode(), key, ips);
			cryptedBytes = ecipher.doFinal(cipherBytes);
		
		} catch (final NoSuchAlgorithmException e) {
			LOGGER.error("KMF: doCrypt : Issue in loading ENCRYPTION Algotithm : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM);
		 } catch (final NoSuchPaddingException e) {
			LOGGER.error("KMF: doCrypt : Padding not supported : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PADDIING);
		 } catch (NoSuchProviderException e) {
			LOGGER.error("KMF: doCrypt : NoSuchProviderException: "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PROVIDER);
		 } catch (InvalidKeyException e) {
			LOGGER.error("KMF: doCrypt : Supplied key is invalid : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY);
		 } catch (InvalidAlgorithmParameterException e) {
			LOGGER.error("KMF: doCrypt : Invalid IV : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_ALG_PARAM);
		 } catch (IllegalBlockSizeException e) {
			LOGGER.error("KMF: doCrypt :IllegalBlockSizeException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_ILLEGAL_BLOCK_SIZE);
		 } catch (BadPaddingException e) {
			LOGGER.error("KMF: doCrypt :BadPaddingException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_BAD_PADDING);
		  } 
		
	 return cryptedBytes;
	}
	
	/**
	 * Used to decrypt actual key based on passphrase.
	 * Passphrase will be passed as -D argument while starting jboss
	 * @param data
	 * @param passPhrase
	 * @return
	 * @throws Exception
	 */
	protected byte[] decryptWithPassPhrase(Key protectorKey, String passPhrase) throws JCCryptoException {
		byte[] cryptoData = null;
		byte[] saltBytes = salt.getBytes();
		try {
			if(passphraseKey==null){
			SecretKeyFactory skf = SecretKeyFactory.getInstance(passphraseAlg, prov);
			KeySpec ks = new PBEKeySpec(passPhrase.toCharArray(),saltBytes, iterationCount, keyLength);
			SecretKey sks = skf.generateSecret(ks);
			passphraseKey = new SecretKeySpec(sks.getEncoded(), keyAlg);
			passphraseCipher = Cipher.getInstance(keyAlg, prov);
			}
			passphraseCipher.init(Cipher.DECRYPT_MODE, passphraseKey);
			cryptoData = passphraseCipher.doFinal(protectorKey.getEncoded());
		} catch (InvalidKeySpecException e) {
			LOGGER.error("KMF: decryptWithPassPhrase : InvalidKeySpecException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("KMF: decryptWithPassPhrase : NoSuchAlgorithmException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM);
		} catch (NoSuchProviderException e) {
			LOGGER.error("KMF: decryptWithPassPhrase : NoSuchProviderException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PROVIDER);
		} catch (NoSuchPaddingException e) {
			LOGGER.error("KMF: decryptWithPassPhrase : NoSuchPaddingException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PADDIING);
		} catch (InvalidKeyException e) {
			LOGGER.error("KMF: decryptWithPassPhrase : InvalidKeyException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY);
		} catch (IllegalBlockSizeException e) {
			LOGGER.error("KMF: decryptWithPassPhrase : IllegalBlockSizeException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_ILLEGAL_BLOCK_SIZE);
		} catch (BadPaddingException e) {
			LOGGER.error("KMF: decryptWithPassPhrase : BadPaddingException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_BAD_PADDING);
		}
	return cryptoData;
	}
	
	/**
	 * To contstruct key object
	 * @param key
	 * @param alg
	 * @return
	 * @throws JCCryptoException
	 */
	public Key constructKey(String key,String alg) throws JCCryptoException{
		SecretKey seckey=new SecretKeySpec(hex.decodeHex(key), alg);
		return seckey;
		}
	
	/**
	 * 
	 * @param data
	 * @param passPhrase
	 * @param mode
	 * @return
	 * @throws JCCryptoException
	 */
	protected byte[] encryptDecryptWithPassPhrase(byte[] data,String passPhrase, boolean mode) throws JCCryptoException   {
		byte[] cryptoData = null;
		byte[] saltBytes = salt.getBytes();
		Key passphraseKey = null;
		try {
				SecretKeyFactory skf = SecretKeyFactory.getInstance(passphraseAlg, prov);
				KeySpec ks = new PBEKeySpec(passPhrase.toCharArray(),saltBytes, iterationCount, keyLength);
				SecretKey sks = skf.generateSecret(ks);
				passphraseKey = new SecretKeySpec(sks.getEncoded(), keyAlg);
				passphraseCipher = Cipher.getInstance(keyAlg, prov);
			if (mode == true) {
				passphraseCipher.init(Cipher.ENCRYPT_MODE, passphraseKey);
				cryptoData = passphraseCipher.doFinal(data);
			} else if (mode == false) {
				passphraseCipher.init(Cipher.DECRYPT_MODE, passphraseKey);
				cryptoData = passphraseCipher.doFinal(data);
			}
			return cryptoData;
		} catch (InvalidKeySpecException e) {
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : InvalidKeySpecException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : NoSuchAlgorithmException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM);
		} catch (NoSuchProviderException e) {
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : NoSuchProviderException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PROVIDER);
		} catch (NoSuchPaddingException e) {
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : NoSuchPaddingException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PADDIING);
		} catch (final IllegalStateException e) { 
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : IllegalStateException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_ILLEGAL_STATE);
		} catch (final IllegalBlockSizeException e) {
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : IllegalBlockSizeException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_ILLEGAL_BLOCK_SIZE);
		} catch (final BadPaddingException e) {
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : BadPaddingException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_BAD_PADDING);
		} catch (InvalidKeyException e) {
			LOGGER.error("KMF: encryptDecryptWithPassPhrase : InvalidKeyException : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY);
		}
	}
	
	
	/**
	 * Loads KeyStore File  
	 * @param storeType
	 * @param storeProvider
	 * @param keyStoreFilePath
	 * @param storePassword
	 * @return
	 * @throws JCCryptoException
	 */
	protected KeyStore loadKeyStore(String storeType, String storeProvider,String keyStoreFilePath, char[] storePassword) throws JCCryptoException {
		KeyStore keyStore=null;
			try {
				keyStore = KeyStore.getInstance(storeType, storeProvider);
				keyStore.load(new FileInputStream(keyStoreFilePath), storePassword);
			} catch (KeyStoreException e) {
				LOGGER.error("KMF: loadKeyStore : UnsupportedEncodingException "+storeType);
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KETSTORE_EXCEPTION,e);
			} catch (NoSuchProviderException e) {
				LOGGER.error("KMF: loadKeyStore : NoSuchProviderException "+storeProvider);
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_PROVIDER,e);
			} catch (NoSuchAlgorithmException e) {
				LOGGER.error("KMF: loadKeyStore : NoSuchAlgorithmException ");
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM,e);
			} catch (CertificateException e) {
				LOGGER.error("KMF: loadKeyStore : UnsupportedEncodingException ");
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_CERTIFICATE_EXCEPTION,e);
			} catch (FileNotFoundException e) {
				LOGGER.error("KMF: loadKeyStore : FileNotFoundException "+keyStoreFilePath);
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KETSTORE_EXCEPTION,e);
			} catch (IOException e) {
				LOGGER.error("KMF: LoadKeyStore : IOException "+keyStoreFilePath);
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KETSTORE_EXCEPTION,e);
			}
		return keyStore;
	}
	
	/**
	 * Loads Private Key from Keystore File
	 * @param keyStore
	 * @param aliasName
	 * @param keyPassword
	 * @return
	 * @throws JCCryptoException
	 */
	protected PrivateKey loadPrivateKey(KeyStore keyStore,String aliasName, char[] keyPassword) throws JCCryptoException{
		PrivateKey pvtKey = null;
		boolean isKeyEntry = false, isEntryExists = false;
		KeyStore.PasswordProtection passWord = null;
		try {
			isEntryExists = keyStore.containsAlias(aliasName);
			isKeyEntry = keyStore.isKeyEntry(aliasName);
			if (isEntryExists == true && isKeyEntry == true) {
				passWord = new KeyStore.PasswordProtection(keyPassword);
				KeyStore.PrivateKeyEntry pvtEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(aliasName, passWord);
				pvtKey = pvtEntry.getPrivateKey();
				passWord.destroy();
			} else {
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KETSTORE_EXCEPTION);
			}
		   } catch (KeyStoreException e) {
			   LOGGER.error("KMF: loadPrivateKey : KeyStoreException " + aliasName);
			  throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KETSTORE_EXCEPTION,e);
		   } catch (NoSuchAlgorithmException e) {
			  LOGGER.error("KMF: loadPrivateKey : NoSuchAlgorithmException");
			  throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NOSUCH_ALGORITHM,e);
		  } catch (UnrecoverableEntryException e) {
		 	 LOGGER.error("KMF: loadPrivateKey : UnrecoverableEntryException");
			 throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_UNRECORABLE_ENTRY_EXCEPTION,e);
		  } catch (DestroyFailedException e) {
			LOGGER.error("KMF: loadPrivateKey : DestroyFailedException");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_UNRECORABLE_ENTRY_EXCEPTION,e);
		}
		
		return pvtKey;
	}
	
	/**
	 * Loads Certificate from KeyStore File
	 * @param keyStore
	 * @param aliasName
	 * @return
	 * @throws JCCryptoException
	 */
	
	protected Certificate loadCertificateFromKeyStore(KeyStore keyStore,String aliasName) throws JCCryptoException{
		java.security.cert.Certificate loadedCertificate = null;
		boolean isEntryExists = false;
		try {
			isEntryExists = keyStore.containsAlias(aliasName);
			if (isEntryExists) {
				loadedCertificate = keyStore.getCertificate(aliasName);
			} else {
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_CERTIFICATE_EXCEPTION);
			}
		} catch (KeyStoreException kse) {
			LOGGER.error("Error Occurred in loadCertificateFromKeyStore : KeyStoreException" + aliasName);
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KETSTORE_EXCEPTION,kse);
		}
		return loadedCertificate;
	}

	
}
