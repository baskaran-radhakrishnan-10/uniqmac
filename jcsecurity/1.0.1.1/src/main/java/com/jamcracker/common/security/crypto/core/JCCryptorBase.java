package com.jamcracker.common.security.crypto.core;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.jamcracker.common.exception.JCFaultCode;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.sun.identity.shared.encode.Base64;
/**
 * Core abstract class for cryptographic operations 
 * @author kkpushparaj
 *
 */
abstract class JCCryptorBase {
	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger	.getLogger(JCCryptorBase.class.getName());

	//Default initialization vector
	private final byte[] iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	private final IvParameterSpec ips = new IvParameterSpec(iv);
	private final JCHex hex = new JCHex();

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

	// Responsible to perform HMAC
	protected String doHMac(final JCCryptoAlgorithm algorithm, final String salt, final String data) throws JCCryptoException,InvalidKeyException {
		final SecretKeySpec secretKey = new SecretKeySpec(hex.decodeHex(salt),algorithm.algorithmName());
		Mac hMac = null;
		try {
			hMac = Mac.getInstance(algorithm.algorithmName());
		} catch (final NoSuchAlgorithmException e) {
			JCCryptorBase.LOGGER.error("Issue in loading Hashing Algotithm : "	+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		hMac.init(secretKey);
		hMac.update(data.getBytes());
		return Base64.encode(hMac.doFinal());
	}

	// Responsible to perform HASHING
	protected byte[] doHash(final JCCryptoAlgorithm algorithm, final String data) throws JCCryptoException {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance(algorithm.algorithmName());
		} catch (final NoSuchAlgorithmException e) {
			JCCryptorBase.LOGGER.error("Issue in loading HASHING Algotithm : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		md.update(data.getBytes());
		return md.digest();
	}

	//Responsible to perform encrypt/decrypt
	protected byte[] doCrypt(JCCryptoAlgorithm algorithm, String key, final byte[] cipherBytes, CRYTO_MODE cryptoMode)  throws JCCryptoException {
		Cipher ecipher=null;
		byte[] cryptedBytes = null;
		try {
			ecipher = Cipher.getInstance(algorithm.fullName());
		} catch (final NoSuchAlgorithmException e) {
			JCCryptorBase.LOGGER.error("Issue in loading ENCRYPTION Algotithm : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		} catch (final NoSuchPaddingException e) {
			JCCryptorBase.LOGGER.error("Padding not supported : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		
		byte[] raw = hex.decodeHex(key);
		SecretKeySpec skeySpec= new SecretKeySpec(raw, algorithm.algorithmName());
		 
		try {
			ecipher.init(cryptoMode.getCipherMode(), skeySpec, ips);
		} catch (final InvalidKeyException e) {
			JCCryptorBase.LOGGER.error("Supplied key is invalid : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		} catch (final InvalidAlgorithmParameterException e) {
			JCCryptorBase.LOGGER.error("Invalid IV : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		try {
			cryptedBytes = ecipher.doFinal(cipherBytes);
		} catch (final IllegalStateException e) { 
			JCCryptorBase.LOGGER.error("Could not perform crypto operation : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		} catch (final IllegalBlockSizeException e) {
			JCCryptorBase.LOGGER.error("Could not perform crypto operation : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		} catch (final BadPaddingException e) {
			JCCryptorBase.LOGGER.error("Could not perform crypto operation : "+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
		
		return cryptedBytes;
	}
}