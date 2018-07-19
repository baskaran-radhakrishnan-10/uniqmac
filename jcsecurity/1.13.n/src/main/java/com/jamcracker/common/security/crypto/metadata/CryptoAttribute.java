package com.jamcracker.common.security.crypto.metadata;

import java.io.Serializable;
import java.security.Key;

/**
 * 
 * @author marumugam
 * 
 */

public class CryptoAttribute implements Serializable {

	private static final long serialVersionUID = 1L;

	private String algorithm;

	private String provider;

	private Key key;

	private String status;

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public Key getKey() {
		return key;
	}

	public void setKey(Key key) {
		this.key = key;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

}
