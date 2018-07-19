package com.jamcracker.common.security.crypto;

import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

import com.jamcracker.common.security.crypto.core.ICryptor;
import com.jamcracker.common.security.crypto.core.JCCryptoAlgorithm;
import com.jamcracker.common.security.crypto.core.JCCryptoConstants;
import com.jamcracker.common.security.crypto.core.JCCryptor;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;

public class JCCryptorTest {
	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(JCCryptorTest.class.getName());

	ICryptor cryptor = new JCCryptor();

	@Test
	public void testAESKeyGeneration() {
		try {
			final String key = cryptor.generateSecretKey(JCCryptoAlgorithm.AES,JCCryptoConstants.BIT256);
			final SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(),
					JCCryptoAlgorithm.AES.algorithmName());
			Assert.assertEquals(JCCryptoAlgorithm.AES.algorithmName(),
					keySpec.getAlgorithm());
		} catch (final JCCryptoException e) {
			JCCryptorTest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		}
	}

	@Test
	public void testEncryptDecryptAES() {
		final String testStr = new String("jctest128");
		try {
			final String key = cryptor.generateSecretKey(JCCryptoAlgorithm.AES,
					JCCryptoConstants.BIT256);
			final String enc = cryptor.encrypt(JCCryptoAlgorithm.AES, key, testStr);
			final String dec = cryptor.decrypt(JCCryptoAlgorithm.AES, key, enc);
			Assert.assertEquals(true,Arrays.equals(testStr.getBytes(), dec.getBytes()));
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final InvalidKeyException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testMD5() {
		final String testStr = new String("md5test");
		final String preHash = new String("82da61aa724b5d149a9c5dc8682c2a45");
		try {
			final String hash = cryptor.generateHash(JCCryptoAlgorithm.MD5, testStr);
			if(preHash.equals(hash)){
				Assert.assertEquals(true,true);
			}
			else{
				Assert.assertEquals(false,false);
			}
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}


	@Test
	public void testUserHash() {
		final String testStr = "tobehashed";
		try {
			final String salt = cryptor.generateSalt(JCCryptoAlgorithm.HMACSHA512,JCCryptoConstants.SALTSIZE4);
			final String hash1 = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, salt,testStr);
			final String hash2 = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, salt,testStr);

			if(hash1.equals(hash2)) {
				Assert.assertEquals(true, true);
			} else{
				Assert.assertEquals(true, false);
			}
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testUserHashWithDifferentSalts() {
		final String testStr = "tobehashed";
		try {
			final String salt1 = cryptor.generateSalt(JCCryptoAlgorithm.HMACSHA512,JCCryptoConstants.SALTSIZE4);
			final String salt2 = cryptor.generateSalt(JCCryptoAlgorithm.HMACSHA512,JCCryptoConstants.SALTSIZE4);
			final String hash1 = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, salt1,testStr);
			final String hash2 = cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, salt2,testStr);

			if(hash1.equals(hash2)) {
				Assert.assertEquals(false, true);
			} else{
				Assert.assertEquals(true, true);
			}
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void testOneTimePasswordGeneration() {
		try {
			Long[] entropy = {new Long("00278889376534")};
			
			final String pin1 = cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy, 8);
			if(pin1.length() != 8) {
				Assert.assertEquals(false, true);
			} else{
				Assert.assertEquals(true, true);
			}
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
	
	
	@Test
	public void testOneTimePasswordGenerationDuplicate() {
		try {
			Long[] entropy = {new Long("00278889376534")};
			
			final String pin1 = cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy, 8);
			final String pin2 = cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy, 8);
			final String pin3 = cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy, 8);
			
			if(pin1.equals(pin2)) {
				Assert.assertEquals(false, true);
			} else{
				Assert.assertEquals(true, true);
			}
			
			if(pin2.equals(pin3)) {
				Assert.assertEquals(false, true);
			} else{
				Assert.assertEquals(true, true);
			}
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void testOneTimePasswordGenerationWithDirrerentEntropy() {
		try {
			Long[] entropy1 = {new Long("00278889376534")};
			Long[] entropy2 = {new Long("00937650475784")};
			
			
			final String pin1 = cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy1, 8);
			final String pin2 = cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy1, 8);
			final String pin3 = cryptor.generateOneTimePin(JCCryptoAlgorithm.HMACSHA1, entropy2, 8);
			
			if(pin1.equals(pin2)) {
				Assert.assertEquals(false, true);
			} else{
				Assert.assertEquals(true, true);
			}
			
			if(pin2.equals(pin3)) {
				Assert.assertEquals(false, true);
			} else{
				Assert.assertEquals(true, true);
			}
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptorTest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}

}
