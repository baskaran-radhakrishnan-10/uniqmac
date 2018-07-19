/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dto;

import java.util.Date;

import com.jamcracker.common.security.crypto.JCDataLabel;

/**
 * @author marumugam
 *
 */
public class DataLabelInfo {
	private Integer actorId;
	private Integer dataLabelId;
	private JCDataLabel dataLabel;
	private String cryptoKey;
	private Integer keyVersion;
	private String status;
	private Date endDate;
	String algorithm;
	String provider;
	String keyType;
	String keyLength;
	String keyId;
	
	public DataLabelInfo() {
		
	}
	public DataLabelInfo(Integer actorId, JCDataLabel label, String cryptoKey,Integer keyVersion,String status,Date endDate,Integer dataLabelId
			,String algorithm,String provider,String keyType,String keyLength,String keyId) {
		this.actorId=actorId;
		this.dataLabel=label;
		this.cryptoKey=cryptoKey;
		this.keyVersion = keyVersion;
		this.status = status;
		this.endDate=endDate;
		this.dataLabelId=dataLabelId;
		this.algorithm = algorithm;
		this.provider = provider;
		this.keyType= keyType;
		this.keyLength = keyLength;
		this.keyId = keyId;
	}
	public Integer getActorId() {
		return actorId;
	}
	public void setActorId(Integer actorId) {
		this.actorId = actorId;
	}
	public String getCryptoKey() {
		return cryptoKey;
	}
	public void setCryptoKey(String cryptoKey) {
		this.cryptoKey = cryptoKey;
	}
	public JCDataLabel getDataLabel() {
		return dataLabel;
	}
	public void setDataLabel(JCDataLabel dataLabel) {
		this.dataLabel = dataLabel;
	}
	public Integer getKeyVersion() {
		return keyVersion;
	}
	public void setKeyVersion(Integer keyVersion) {
		this.keyVersion = keyVersion;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public Date getEndDate() {
		return endDate;
	}
	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}
	public Integer getDataLabelId() {
		return dataLabelId;
	}
	public void setDataLabelId(Integer dataLabelId) {
		this.dataLabelId = dataLabelId;
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
	public String getKeyType() {
		return keyType;
	}
	public void setKeyType(String keyType) {
		this.keyType = keyType;
	}
	public String getKeyLength() {
		return keyLength;
	}
	public void setKeyLength(String keyLength) {
		this.keyLength = keyLength;
	}
	public String getKeyId() {
		return keyId;
	}
	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}
	
	
	
	
	
}
