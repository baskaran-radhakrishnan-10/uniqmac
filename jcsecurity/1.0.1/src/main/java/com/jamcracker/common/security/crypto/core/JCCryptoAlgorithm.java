package com.jamcracker.common.security.crypto.core;

/**
 * Enum to hold algorithm details.
 * @author kkpushparaj
 *
 */
public enum JCCryptoAlgorithm {
	AES("AES", "OFB","PKCS5Padding"), 
	SHA1_PRNG("SHA1PRNG", "",""),
	HMACSHA512("HmacSHA512","",""),
	HMACSHA1("HmacSHA1","",""),
	MD5("MD5","",""),
	SHA512("SHA-512","","");
	
	private final String algorithmName;
	private final String cipherMode;
	private final String padding;
	
	JCCryptoAlgorithm(final String algorithmName, final String cipherMode,final String padding) {
		this.algorithmName = algorithmName;
		this.cipherMode = cipherMode;
		this.padding = padding;
	}

	public String algorithmName() {
		return algorithmName;
	}

	public String padding() {
		return padding;
	}

	public String cipherMode() {
		return cipherMode;
	}

	public String fullName() {
		String fullName = algorithmName;
		if(!cipherMode.equals("")) {
			fullName += "/";
			fullName += cipherMode;
		}
		if(!padding.equals("")) {
			fullName += "/";
			fullName += padding;
		}
		return fullName;
	}

}


