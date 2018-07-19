/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dto;

import java.security.Key;


/**
 * @author marumugam
 *
 */
public class ProtectorDataLabelInfo {

	private Integer keyVersion;
	private Key protectorKey;
	private String keyString;
	private String algorithm;
	private String provider;
	
	
	public ProtectorDataLabelInfo() {
		
	}
	public ProtectorDataLabelInfo(Integer keyVersion,String keyValue, String algorithm,String provider) {
		this.keyVersion = keyVersion;
		this.keyString=keyValue;
		this.algorithm = algorithm;
		this.provider = provider;
		
	}
	public Integer getKeyVersion() {
		return keyVersion;
	}
	public void setKeyVersion(Integer keyVersion) {
		this.keyVersion = keyVersion;
	}

	
	public Key getProtectorKey() {
		return protectorKey;
	}
	public void setProtectorKey(Key protectorKey) {
		this.protectorKey = protectorKey;
	}
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
	public String getKeyString() {
		return keyString;
	}
	public void setKeyString(String keyString) {
		this.keyString = keyString;
	}
		
	
	
	
	
}
