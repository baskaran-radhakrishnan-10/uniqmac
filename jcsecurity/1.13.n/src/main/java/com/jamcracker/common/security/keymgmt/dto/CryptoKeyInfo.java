/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dto;

import com.jamcracker.common.security.crypto.JCCryptoType;

/**
 * @author tmarum
 *
 */
public class CryptoKeyInfo {
	private Integer actorId;
	private JCCryptoType cryptoType;
	private String cryptoKey;
	
	public CryptoKeyInfo() {
		
	}
	public CryptoKeyInfo(Integer actorId, JCCryptoType cryptoType, String cryptoKey) {
		this.actorId=actorId;
		this.cryptoType=cryptoType;
		this.cryptoKey=cryptoKey;
	}
	public Integer getActorId() {
		return actorId;
	}
	public void setActorId(Integer actorId) {
		this.actorId = actorId;
	}
	public JCCryptoType getCryptoType() {
		return cryptoType;
	}
	public void setCryptoType(JCCryptoType cryptoType) {
		this.cryptoType = cryptoType;
	}
	public String getCryptoKey() {
		return cryptoKey;
	}
	public void setCryptoKey(String cryptoKey) {
		this.cryptoKey = cryptoKey;
	}
	
}
