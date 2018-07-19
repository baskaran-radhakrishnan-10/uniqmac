package com.jamcracker.common.security.crypto;

import java.security.InvalidKeyException;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import com.jamcracker.common.security.crypto.exception.JCCryptoException;

public class JCCryptoAPITest {
	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(JCCryptoAPITest.class.getName());

	ICryptoAPI cryptoAPI = CryptoAPIFactory.getInstance().getCryptoAPI();

	@Test
	public void testWithFixedValues() {
		LOGGER.info("Start testWithFixedValues");
		
		final String salt="e1c464ab9c8963dec3ae80e614b23318ab9b36d7d8ea891178689603437a6efb9948238d652f1bd77d7636c480729be1a6b885c69b0474c9f4307269fb43f8024598c3757214b81f0c02032d4cbe1ec7a03864da585d8c79f81b33a267e9dd70babcbcbbbb37ea06325c9141c220593fcb0d3f24b13b3a6210ac9e4a432a04172b9617b5a4ae1359389fd051dccf6edbfc73ae1921b01d4ee16ab6327f741ee74a03869ba4fc587fe3b723c3c6a9a23becc96ea42ae2d476e3a8c6d0d1cd7a10a65194d9b0248a8123cccde92a3c9a1a6af4002d6b4e83fd93859e9e8accbf7d1694436c8b2eee6331a3ef506a0d35fd9ea0f0324673648b38891d01481b367607bf58333e0c90ac43fcc327afeb42fb0e6297d7844206cbab234069eb2eef9fd8933dda79e073992cc8840dcf065f9ba8b74b1790a55765d05c8d8ba9389bc5c270a04fb9f594e63d0e101794438c50460ffbbaa922d47af5df6e5d917eab2c798337bb4bbfad3bc0fdd66645ff29c93f922c9de7f726670fdf624ebfa9974e1e9f025367b2344c5580bfbb383fd977727be20bbae1e7ee7fe31ce6dc6740d742b04340d10e0fd52dd27fdbd433b73e05f113768c61e9ddcbdbc9bbfeeb6d5f2917ff884cb1d509e91520c5d2514af5fd2b0373722f93acbeb4a46b02c6a240d16b00468e4c385c01384a7b29db48910154275b1ba4d9c5d0b81d6e2dd187320c5e450659f96624f4b0004a4f8d45c746b9bf88c44cd75338291e991f231e4220786e648f30f3647686192572f5614b6e014a07131506fc2f99a5ac5e6380518b3ec9683958ea955686c2885dff31694cd531129838d7c24b7193bad093efed2e0106bdbd8dbc421c169cc5f82bb95f58172db4d39d0a9543663ece5693267bf1b301a87f25d358f9b03893f9570c10ce655b221e7e7c6653e662ee94816f73a413cf5b84898072a942dd1e87fd0a5f29eabdbf6200d8edcbdbb17ee0026d6d0d9631b4bd038def9e38a56e10536a2989a8ab55c70371f88917d76ab076f32c1c7ea0bf587d863af61609805fa3b6d56197c2c9835ae793cac011712bbe49ebf3a759e11bee9883d444b1e66348debc3625f106371db019f15ad3af7ce1783e92e4aedfb49705c70d8216c951a64e4fdff6b6bdfc209ece7b6e0bfbbc2d46e64680ed1faef0122c21da0fbc6606607be7adb70e3a4397050d7095daa980158b1007211a638121ffa21560a89762e24960986a778dd11ed7ff399cb753bf1e46e4364bc108e0eefbae45f9938beec1f703ae0e36ee5e579830994454b587f13390ce6ab1828fd62ca6a4d00cac7a096d530befbf6cbd3e3b3f4e041743ab0833cb714defd19ac44f863ae5449e618d419bc559c1401094779020772223a11cd02b04f0a53050de332619a58d97321e53548cd6457f58e6cb06a60e2f47625d6e128f89b55c649013a04f2d918d469b15e098e7c4c4ab28a93d2f60250d47040759d0771764250f8623af5166ad513c6a45a85e8498a492c07a089939657e7a34681066138547e1ab301690722c693fd840d4dc1945afedd56f68a15c13622dd08920f986109f9558e2e377640d2fbaca3e7895496ee2cf49c8d33d88f18adabcce72e159f8bbddba085c8d808c3a78caab7816f4113783fc13b99dce2d70b591b485fd200076a961538543c36fa99d39cb2f8dcf60c5d350c9308944758835a36ca9f5242920381e40eb75c68a1fd185db6d592dbe3fa5e20d695b7747403afab487f567bb1def7cb1e19f566be1759448df17b5b60c02cbe3dd0cd41e52f99fb302c16cf5c06f00054d481d1362065a4716b81d61596b9e4854268588dba9b07944828a1d98991f41a6fdcbc1b60f8b774f600b3929ca773a0fa954066c5827fa1f6908b1d3cc1d2fae5a2e30bac8d78f0f43a95104b3c94078201395d8e27a6a98e7e00f04288a1840613a29c5f4e4bd3a9a75f9d9891fa96ffbbc14cb63ebb9fdc392dcd327dd13e2b205ab40eeb86dfc5e4dea1e3709367f91e2123e1d5a00d134cb15abdb4815e44532e931696c8b90e1e18c2c6e6613f05214ad4397d82a7fd326aa2420cc51c3cef7787fcb7f5865cc643305114aeee7894e3975d1c4a8f5290e7ad7cf4873b7a130b4ddddcf75ef4bef4ce63b6298941e76643ecdcb479b16908f1d2e3293ee2ce90d0b76d8b8252bbf0e9145d26dbf6fa2708d73b5bb490ad6a85720399df6e4c7eeec757fb71fada26417949071672b609815e00b83aa6d5ce0ef15fafbe377da89f43e36d41d80c765721e9caf96f30d6ff918512c02b3cedce605ba7c4295191b0fad3835e7609761ebb743c3a9cd1bf117f3cb8f3c92d9ea9727ca1b0022bcb78202f83f77cbf4670da30ef4b29f45fb02b9c72abc3537d9e8a0e3b483345c27e790629f89293c7e36aab93e15bf79351cd3a49b235c36bcd57ccbaea34112890eb0c8b0d73e1380b05b1b8d24eec2553df92192a7d998642721f00ca368666c5e0b7598629d6a0cf6e8d7574e75bc70b60b2084a48dc6cb714a2bf8b482c86cab438ed42aed306aba655279aa74903fbb4905b69274c10a149ba279296b7259282e1da6c23b6780ddb195e493426625d06e10384d9efa6eac4a62a6452c663a8de3b974941bb25a895b83731944f043c0446e3c181ab28a9297e60f9226e72c32b3063b211db41fde5e5e9e418c16c1108e783a3003292cb94255b6aa589625e0e9a87435ec9ca40530fd5bf76fac211ea506b5928b5132e06dad9e7143f62634ffbe03d395992f22339f0ae0105cc4bc09925b2313cc289099d76956480b13b9211e8e30cc049486828c902705b9af1c43059ba4c01a5de7e65e07d665bcef6b95af82e359939c99a40241ef48c217f241261c956f066fbbefa058df7bcded42317f977370114b5185a0dbafb3e59619810e0c1d3a4a81880823fa8fce42c6340ecdb6e5a8984bbbabddcb0f04ce415a86ccc9826217c97f0d334d5ca8710e9b3378158d911acd3f24946911045052ce83ba06b48cc8a3a07faa36d7b07dd0efa482d99b1d59dd0bd1582c0b326efbbe4f654724d1de24c9e62998836b03e4dff62a31d84eb6909679f952ade9524df9b585918e8bf00be15e884fe38411e2fdd19de81f41f530d29f83b363d3a5dcbcb97de0b8872ac6857b3a9497be4be0c028094a23ca77cf984ac84c4c75a797ffc2f125ff863a7e797579515ebad208e552f11508697c21df7e148f463e62d1bde599616ab52bbb6eaab7b9e840d0bc401471dfa0b893c3b6aff8e23aa3bebf857161439b2ab7d58a65232c6a885f5e0aeab1007d93dd2b794a6764b3200124012c56915c61aab210fd775469ea7c0c5f9929c93059f2ffc359f3fc3cbe94678fd4f8c8bfb2752b66414ce9186da12dd9459fd0e960b21c740f3ff98a6b2ab92e491ac66869337e8d780da8cc604878acd9c806f567185d9e9a47f10399cec6c3eb143f6f49e89a4f4c7de0a0bc2d23f555f3233fca091b13dc645481a12bf1ee6789490e7674c3f420ba5155506c851e53c03ddde1bf34c2d96dc0db67e58fed8ed92f6e60c438d9eb29b9aa95f12eb394cd890853e7e2fe872b8118d98bfa229f4225788ff83f7fbb5c63868d8645048b075415682e0a129f66fc8c564361f1ffcdbf5d5a5cde1c1e5f1e64158130b0c5607305115828311c373205afdb773d9c6613a6166cb706a1f2b9ffde54098ce40ece0a154ca472e4a42fa00d1ef6cdfc02b5e9d9546bd0c197cf26ab50565925d0928b78c66fa311175b4ef522b32b42ebd9a69ac17586f8f3f00eb3149bf1c9a7692b71db4ceb7965f9a78bf8d593a22ea79f16a1daafc33c45564cfba6b24daf18fdc51e80200f41fd0899dda147d6d34449f00c96c7cda40a68874d24bb9906a04bee53394b3af3be65d800d79874fe8b615b3fb67abfa319752303a58f2c4d36e6f2c06364b63f8ecf6c8152e21eeebd724a54e408dd3f4736c085300b4541b20834040e8353985e2450022285c46ee179e99690ace6bb1e957df4e8a83de17b90a29098ca9c1cd6fd5c38f46808c972f4e0f8043eebd6b5c4f6befb1512d148d20c3576096e94cff258fd589a0073aae0ea40a111d1b355107ac0e3791fe0e40ee9f2b1e408b3b5ff8a26384e625f9ef32bb366bdf7aaaf8136149bfbcb2de52370c3f90a13282afb3a4535d76526bba89eb4e41a26ae32588936033f9fcd21958924b37a1ee951615ac6e6d1fc5c7c02708f79de982414b7be9c6dfff81dd328031d408989cbcab6d0909f0f009af5669df9d0669accf7394db2128f2fede2b82dad8524a4a6d1869196c39b661605d4317f8f7802c9aab9dac1f149afb844b169b960d1de852713e6a8a2f5b579dcdb8098b9b39603a83c85be1402d8eabd3aaa2820a83f7b68065ac3d97c1f7a4afb6dd10839e33748fd7fda67b549454d444d80ef7a83e9c7f6059a63583416e42f1fe4f723d350b2ed5929e0c7fcf992aca0edfdc542f3e3a6652e9ade5f855cbf82a2a80fe0c62b9e1a9fd4e903e3637439ecc45290912c1a53c8ebce80a319a7abc54589c7613a21456af46df57b325f2d986cf4b32306a31c02a66949985028bcb3bfb515fb5a6063cc19eed94387247b13625e15b41a31fe6afe56cff0faeb9755fd8aa43e3dc0b9e20794745aaac20e00e4d24397e0902c7f9b529fde91c18b2575359103f576326d8c33cdad6c1bfbaeebc64790787eddd3366b6a39be8f25446cf98589960a51be592a1d8ec8bd4e2b94c564bcf09a7c3316b3b12ece7c20242cbee4ad2dc7b9b9afc86842877b85fdfb304ab9f804b305766f122dec0a4120a59681c868776c796feb9d70d8f5976ca3e3bfcc99aa90d272fe94e243c825fb9e596133f88b1ca6ed1fd19fd8caf90cf2c3431d3c0946401dc80eb354dc891615da8a70200178913c73ccd439861c03c693d1599bb9e436214add1f20d9cb81f0f87d7883d5227a4ecbca83f6917f86521994597533588d073a6af252d859bbe21c55bdc27b23e6e1a213addca55f7de47933958fe57d65c2b4836fef67bb0ac202bc8ddf136e4d4a86e2b64a5b84555414a3005857ccf2fc0a80bff3b4a8c3911b05131b997555cee633c9b20e246a45acf112885858cd598bcebdf5aceb1cb6892e6265e4f8ecb9f9cea6d3df856d384f801deb644e4e13cad0c657b984d5f72c715b511771b012cf981d5f266cb67a17b1025586905c0be63bed30965accf6e5407f6e816b0323c22cebe082b67ecdf0c1a67272e43ffe87da0bb7f3a2de5453c77c41d749f045ddbb2390aa2f0124679e23b9925ddebf72bb6a053e1e5a2407eb9cd3ba039e4f0be457b81be2eccaa39030861556e39dd238aa55de606d043fc0440ee0457235928c998c834aa90233aa014adb76be1d40265e196b2f713d831ae42c1f53287a629a2b72c853f28eef7c468b50dfb1287c5a4c8e438532b45d78e7a77497eb0d8670a5726eee7565377daaf033070a3577facf5aad37c7117585388c7fc0caece00d55cca1f57bc107a9e6c4ea82db8f566139fe9693a61f792f83eda39d6b08b9521531cd72d825e45ab2327702e9b0eaa6ac1523da2b9f6505cbd246db5144d43d96927f8eef0ba35d6b7ac984c3891a79afb0936ae2acf5814a6b896156183cd45e666fabf574f8f41dd8bdc6ed5bca77bff9c561d88129a9b03676d44d2a5411ad438855d7d52f98493534e906ca76fa921de04e993c909eedac738fba8e9f7f9c9d4ec73d870879344223efc6fef01e67";
		final String userPaswordHash1 = "UsaVJYT2PxutIRUfATnH9zekIadzCMZL8FQtTbai1TndaVs0oKdjNUoXUGvSIayrLM8a1R8UF9e0ZUx2xrosuQ==";

		try {
			final String userPaswordHash2 = cryptoAPI.generateHMAC(JCCryptoType.USER_PASSWORD, salt, "fixedvaluetest");
			
			LOGGER.info("Salt "+ salt);
			LOGGER.info("User password 1 "+ userPaswordHash1);
			LOGGER.info("User password 1 "+ userPaswordHash2);
			
			if(userPaswordHash1.equals(userPaswordHash2)) {
				Assert.assertEquals(true, true);
			} else{
				Assert.assertEquals(true, false);
			}
			LOGGER.info("End testWithFixedValues");
		} catch (final JCCryptoException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final InvalidKeyException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		}
	}
	
	@Test
	public void testUserPasswordHash()  {
		try {
			LOGGER.info("Start  testUserPasswordHash");
			final String salt = cryptoAPI.generateSalt(JCCryptoType.USER_PASSWORD);
			final String userPaswordHash1 = cryptoAPI.generateHMAC(JCCryptoType.USER_PASSWORD, salt, "P@ssw0rd");
			final String userPaswordHash2 = cryptoAPI.generateHMAC(JCCryptoType.USER_PASSWORD, salt, "P@ssw0rd");

			LOGGER.info("Salt "+ salt);
			LOGGER.info("User password 1 "+ userPaswordHash1);
			LOGGER.info("User password 2 "+ userPaswordHash2);
			
			if(userPaswordHash1.equals(userPaswordHash2)) {
				Assert.assertEquals(true, true);
			} else{
				Assert.assertEquals(true, false);
			}
		} catch (final JCCryptoException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final InvalidKeyException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		}
		LOGGER.info("End  testUserPasswordHash");
	}


	@Test
	public void testCreditCardEncryptionDecryption()  {
		LOGGER.info("Start  testCreditCardEncryptionDecryption");
		final String ccNumber = "1234 5678 1234 1234";
		try {
			final String key = cryptoAPI.generateKey(JCCryptoType.CREDIT_CARD);
			final String enc = cryptoAPI.encrypt(JCCryptoType.CREDIT_CARD, ccNumber,key);
			final String dec = cryptoAPI.decrypt(JCCryptoType.CREDIT_CARD, enc, key);

			LOGGER.info("Key "+ key);
			LOGGER.info("Encrypt "+ enc);
			LOGGER.info("Decrypt "+ dec);

			if(Arrays.equals(dec.getBytes(), ccNumber.getBytes())){
				Assert.assertEquals(true, true);
			} else{
				Assert.assertEquals(true, false);
			}
		} catch (final JCCryptoException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final InvalidKeyException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		}
		LOGGER.info("End  testCreditCardEncryptionDecryption");
	}


	@Test
	public void testPersonalDataEncryptionDecryption()  {
		LOGGER.info("Start  testPersonalDataEncryptionDecryption");
		final String pData = "Jamcracker employee";
		try {
			final String key = cryptoAPI.generateKey(JCCryptoType.PERSONAL_DATA);
			final String enc = cryptoAPI.encrypt(JCCryptoType.PERSONAL_DATA, pData,key);
			final String dec = cryptoAPI.decrypt(JCCryptoType.PERSONAL_DATA, enc, key);

			LOGGER.info("Key "+ key);
			LOGGER.info("Encrypt "+ enc);
			LOGGER.info("Decrypt "+ dec);
			
			if(Arrays.equals(dec.getBytes(), pData.getBytes())){
				Assert.assertEquals(true, true);
			} else{
				Assert.assertEquals(true, false);
			}
		} catch (final JCCryptoException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final InvalidKeyException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		}
		LOGGER.info("End  testPersonalDataEncryptionDecryption");
	}


	@Test
	public void testServicePasswordEncryptionDecryption()  {
		LOGGER.info("Start  testServicePasswordEncryptionDecryption");
		final String pData = "Service password";
		try {
			final String key = cryptoAPI.generateKey(JCCryptoType.SERVICE_PASSWORD);
			final String enc = cryptoAPI.encrypt(JCCryptoType.SERVICE_PASSWORD, pData,key);
			final String dec = cryptoAPI.decrypt(JCCryptoType.SERVICE_PASSWORD, enc, key);

			LOGGER.info("Key "+ key);
			LOGGER.info("Encrypt "+ enc);
			LOGGER.info("Decrypt "+ dec);
			
			if(Arrays.equals(dec.getBytes(), pData.getBytes())){
				Assert.assertEquals(true, true);
			} else{
				Assert.assertEquals(true, false);
			}
		} catch (final JCCryptoException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final InvalidKeyException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		}
		LOGGER.info("End  testServicePasswordEncryptionDecryption");
	}


	@Test
	public void testURLEncryptionDecryption()  {
		LOGGER.info("Start  testURLEncryptionDecryption");
		final String pData = "http://mail.yahoo.com?data=null&p=jhjsd";
		try {
			final String key = cryptoAPI.generateKey(JCCryptoType.URL);
			final String enc = cryptoAPI.encrypt(JCCryptoType.URL, pData,key);
			final String dec = cryptoAPI.decrypt(JCCryptoType.URL, enc, key);

			LOGGER.info("Key "+ key);
			LOGGER.info("Encrypt "+ enc);
			LOGGER.info("Decrypt "+ dec);
			
			if(Arrays.equals(dec.getBytes(), pData.getBytes())){
				Assert.assertEquals(true, true);
			} else{
				Assert.assertEquals(true, false);
			}
		} catch (final JCCryptoException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final InvalidKeyException e) {
			JCCryptoAPITest.LOGGER.error(e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		}
		LOGGER.info("End  testURLEncryptionDecryption");
	}
	
	@Test
	public void testOneTimePasswordGeneration() {
		LOGGER.info("Start  testOneTimePasswordGeneration");
		try {
			Long[] entropy = {new Long("00278889376534")};
			final String pin = cryptoAPI.generateOneTimePin(entropy);
			
			LOGGER.info("entropy "+ entropy);
			LOGGER.info("pin "+ pin);
			
			if(pin.length() != 8) {
				Assert.assertEquals(false, true);
			} else{
				Assert.assertEquals(true, true);
			}
		} catch (final JCCryptoException e) {
			e.printStackTrace();
			JCCryptoAPITest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
		LOGGER.info("End  testOneTimePasswordGeneration");
	}
	
	@Test
	public void testOneTimePasswordGenerationWithDirrerentEntropy() {
		LOGGER.info("Start testOneTimePasswordGenerationWithDirrerentEntropy");
		try {
			Long[] entropy1 = {new Long("00278889376534")};
			Long[] entropy2 = {new Long("00937650475784")};
		
			final String pin1 = cryptoAPI.generateOneTimePin(entropy1);
			final String pin2 = cryptoAPI.generateOneTimePin(entropy1);
			final String pin3 = cryptoAPI.generateOneTimePin(entropy2);
			
			LOGGER.info("entropy1 "+ entropy1);
			LOGGER.info("entropy2 "+ entropy2);
			
			LOGGER.info("pin 1 "+ pin1);
			LOGGER.info("pin 2 "+ pin2);
			LOGGER.info("pin 3 "+ pin3);
						
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
			JCCryptoAPITest.LOGGER.error("Crypto operation failure" + e.getLocalizedMessage());
			Assert.assertEquals(true, false);
		} catch (final Exception e) {
			e.printStackTrace();
		}
		LOGGER.info("End testOneTimePasswordGenerationWithDirrerentEntropy");
	}

}
