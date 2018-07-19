package com.jamcracker.common.security.crypto.core;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

import com.jamcracker.common.exception.JCFaultCode;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
/**
 * Class responsible for generating key and salts for cryptographic operations
 * @author kkpushparaj
 *
 */
class Generator {
	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(Generator.class.getName());

	private int size;
	private JCCryptoAlgorithm algorithm = JCCryptoAlgorithm.AES;
	private final long SEED_VALUE = 999999999;
	private final JCHex hex = new JCHex();

	/*
	 * Constructor block
	 */
	@SuppressWarnings("unused")
	private Generator() {
	}

	public Generator(final JCCryptoAlgorithm algorithm, final int size) {
		setAlgorithm(algorithm);
		setSize(size);
	}

	public int getSize() {
		return size;
	}

	public final void setSize(final int size) {
		this.size = size;
	}

	public JCCryptoAlgorithm getAlgorithm() {
		return algorithm;
	}

	public final void setAlgorithm(final JCCryptoAlgorithm algorithm) {
		this. algorithm = algorithm;
	}

	/**
	 * Responsible for generate key for cryptographic purposes.
	 * @return key in Hex format
	 * @throws JCCryptoException
	 */
	public synchronized String generateKey() throws JCCryptoException {
		String keyString = new String();
		try {
			final KeyGenerator kgen = KeyGenerator.getInstance(getAlgorithm().algorithmName());
			kgen.init(getSize());
			final Key key = kgen.generateKey();
			final byte[] raw =key.getEncoded();
			keyString =new String(hex.encodeHex(raw));
		} catch (final NoSuchAlgorithmException e) {
			Generator.LOGGER.error("Issue in loading the Algorithm :"+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		} 
		return keyString;
	}
	
	/**
	 * Responsible for getting salts based on the size defined. Supported sizes are 512,1024,2098,4096
	 * @return salt in base64 format
	 * @throws JCCryptoException
	 */
	public synchronized String generateSalt() throws JCCryptoException {
		try {
			final int saltSize = getSize();
			final byte[] RandomBytes_1 = new byte[1024];
			final byte[] RandomBytes_2 = new byte[1024];
			final byte[] RandomBytes_3 = new byte[1024];
			final byte[] RandomBytes_4 = new byte[1024];
			byte[] randomBytes5;

			final SecureRandom prng = SecureRandom.getInstance(JCCryptoAlgorithm.SHA1_PRNG.algorithmName());
			prng.setSeed(SEED_VALUE * System.nanoTime());

			switch (saltSize) {
			case JCCryptoConstants.SALTSIZE1:
				prng.nextBytes(RandomBytes_1);
				randomBytes5 = new byte[RandomBytes_1.length];
				System.arraycopy(RandomBytes_1, 0, randomBytes5, 0,RandomBytes_1.length);
				break;
			case JCCryptoConstants.SALTSIZE2:
				prng.nextBytes(RandomBytes_1);
				prng.nextBytes(RandomBytes_2);
				randomBytes5 = new byte[RandomBytes_1.length+ RandomBytes_2.length];
				System.arraycopy(RandomBytes_1, 0, randomBytes5, 0,RandomBytes_1.length);
				System.arraycopy(RandomBytes_2, 0, randomBytes5,RandomBytes_2.length, RandomBytes_2.length);
				break;
			case JCCryptoConstants.SALTSIZE3:
				prng.nextBytes(RandomBytes_1);
				prng.nextBytes(RandomBytes_2);
				prng.nextBytes(RandomBytes_3);
				randomBytes5 = new byte[RandomBytes_1.length+ RandomBytes_2.length + RandomBytes_3.length];
				System.arraycopy(RandomBytes_1, 0, randomBytes5, 0,RandomBytes_1.length);
				System.arraycopy(RandomBytes_2, 0, randomBytes5,RandomBytes_2.length, RandomBytes_2.length);
				System.arraycopy(RandomBytes_3, 0, randomBytes5,RandomBytes_2.length + RandomBytes_3.length,RandomBytes_3.length);
				break;
			default:
				prng.nextBytes(RandomBytes_1);
				prng.nextBytes(RandomBytes_2);
				prng.nextBytes(RandomBytes_3);
				prng.nextBytes(RandomBytes_4);
				randomBytes5 = new byte[RandomBytes_1.length+ RandomBytes_2.length + RandomBytes_3.length+ RandomBytes_4.length];
				System.arraycopy(RandomBytes_1, 0, randomBytes5, 0,RandomBytes_1.length);
				System.arraycopy(RandomBytes_2, 0, randomBytes5,RandomBytes_2.length, RandomBytes_2.length);
				System.arraycopy(RandomBytes_3, 0, randomBytes5,RandomBytes_2.length + RandomBytes_3.length,RandomBytes_3.length);
				System.arraycopy(RandomBytes_4, 0, randomBytes5,RandomBytes_2.length + RandomBytes_3.length+ RandomBytes_4.length, RandomBytes_4.length);
				break;
			}
			return new String(hex.encodeHex(randomBytes5));
		} catch (final NoSuchAlgorithmException e) {
			Generator.LOGGER.error("Error generating in SALT: "	+ e.getLocalizedMessage());
			throw new JCCryptoException(JCFaultCode.getFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE));
		}
	}
}