/*
 * 
 * Class: DataLabels.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Jun 7, 2014   Muthusamy		1.0			Initial version.DTO Holds CryptoGraphy Metadata DataLabel information
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
package com.jamcracker.common.security.keymgmt.dto;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "labels")
@XmlType(propOrder = { 
					 "id",
					 "keyType",
					 "keyLength",
					 "algorithm",
					 "providerName",
					 "distributionType",
					 "keyId",
					 "encryptDecrypt",
					 "signVerify",
					 "hmac",
					 "expiryDate",
					 "previousKeyVersion",
					 "currentKeyVersion" ,
					 "cryptoCapability",
					 "encryptedPersistence"
					 })
public class DataLabels {

	private String id;

	private String keyType;

	private String algorithm;

	private int keyLength;

	private String providerName;

	private String distributionType;

	private String keyId;

	private String encryptDecrypt;

	private String signVerify;

	private String hmac;

	private String previousKeyVersion;

	private String currentKeyVersion;

	private String expiryDate;

	/**
	 * @return the cryptoCapability
	 */
	public String getCryptoCapability() {
		return cryptoCapability;
	}

	
	private String cryptoCapability;

	private String encryptedPersistence;

	/**
	 * @return
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id
	 */
	@XmlAttribute
	public void setId(String ids) {
		id = ids;
	}

	/**
	 * @return
	 */
	public String getKeyType() {
		return keyType;
	}

	/**
	 * @param keyType
	 */
	@XmlElement
	public void setKeyType(String keyType) {
		this.keyType = keyType;
	}

	/**
	 * @return
	 */
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * @param algorithm
	 */
	@XmlElement
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * @return
	 */
	public int getKeyLength() {
		return keyLength;
	}

	/**
	 * @param keyLength
	 */
	@XmlElement
	public void setKeyLength(int keyLength) {
		this.keyLength = keyLength;
	}

	/**
	 * @return
	 */
	public String getProviderName() {
		return providerName;
	}

	/**
	 * @param providerName
	 */
	@XmlElement
	public void setProviderName(String providerName) {
		this.providerName = providerName;
	}

	/**
	 * @return
	 */
	public String getDistributionType() {
		return distributionType;
	}

	/**
	 * @param distributionType
	 */
	@XmlElement
	public void setDistributionType(String distributionType) {
		this.distributionType = distributionType;
	}

	/**
	 * @return
	 */
	public String getKeyId() {
		return keyId;
	}

	/**
	 * @param keyId
	 */
	@XmlElement
	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}

	/**
	 * @return
	 */
	public String getEncryptDecrypt() {
		return encryptDecrypt;
	}

	/**
	 * @param encryptDecrypt
	 */
	@XmlElement
	public void setEncryptDecrypt(String encryptDecrypt) {
		this.encryptDecrypt = encryptDecrypt;
	}

	/**
	 * @return
	 */
	public String getSignVerify() {
		return signVerify;
	}

	/**
	 * @param signVerify
	 */
	@XmlElement
	public void setSignVerify(String signVerify) {
		this.signVerify = signVerify;
	}

	/**
	 * @return
	 */
	public String getHmac() {
		return hmac;
	}

	/**
	 * @param hmac
	 */
	@XmlElement
	public void setHmac(String hmac) {
		this.hmac = hmac;
	}
	
	/**
	 * @return
	 */
	public String getPreviousKeyVersion() {
		return previousKeyVersion;
	}

	/**
	 * @param previousKeyVersion
	 */
	@XmlElement
	public void setPreviousKeyVersion(String previousKeyVersion) {
		this.previousKeyVersion = previousKeyVersion;
	}

	/**
	 * @return
	 */
	public String getCurrentKeyVersion() {
		return currentKeyVersion;
	}

	/**
	 * @param currentKeyVersion
	 */
	@XmlElement
	public void setCurrentKeyVersion(String currentKeyVersion) {
		this.currentKeyVersion = currentKeyVersion;
	}

	/**
	 * @return
	 */
	public String getExpiryDate() {
		return expiryDate;
	}

	/**
	 * @param expiryDate
	 */
	@XmlElement
	public void setExpiryDate(String expiryDate) {
		this.expiryDate = expiryDate;
	}
	
	/**
	 * @param cryptoCapability
	 */
	@XmlElement
	public void setCryptoCapability(String cryptoCapability) {
		this.cryptoCapability = cryptoCapability;
	}

	/**
	 * @return the encryptedPersistence
	 */
	public String getEncryptedPersistence() {
		return encryptedPersistence;
	}

	/**
	 * @param encryptedPersistence
	 */
	@XmlElement
	public void setEncryptedPersistence(String encryptedPersistence) {
		this.encryptedPersistence = encryptedPersistence;
	}
}