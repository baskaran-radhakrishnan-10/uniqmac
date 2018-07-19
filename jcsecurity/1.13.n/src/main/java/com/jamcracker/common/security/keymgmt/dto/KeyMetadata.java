/*
 * 
 * Class: KeyMetadata.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Jun 7, 2014   Muthusamy		1.0			Initial version.DTO Holds CryptoGraphy Metadata information defined by KMF
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

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "properties")
@XmlType(propOrder = {
						"owner", 
						"user",
						"userId",
						"group", 
						"project", 
						"currentState",
						"distributionPath", 
						"requestDate", 
						"approvalDate",
						"approvedBy", 
						"creationDate", 
						"labels", 
						"kmfSig"
						
						})
public class KeyMetadata {

	private String owner;

	private String user;
	
	private String userId;

	private String group;

	private String project;

	private String currentState;

	private String distributionPath;

	private String requestDate;

	private String approvalDate;

	private String approvedBy;

	private String creationDate;
	
	private DataLabels labels;

	private String kmfSig;

	private String stringValue;
	
	/**
	 * @return
	 */
	public String getOwner() {
		return owner;
	}

	/**
	 * @param owner
	 */
	public void setOwner(String owner) {
		this.owner = owner;
	}

	/**
	 * @return
	 */
	public String getUser() {
		return user;
	}
	
	/**
	 * @param user
	 */
	public void setUser(String user) {
		this.user = user;
	}
	

	/**
	 * @return
	 */
	public String getUserId() {
		return userId;
	}

	/**
	 * @param userId
	 */
	public void setUserId(String userId) {
		this.userId = userId;
	}
	/**
	 * @return
	 */
	public String getGroup() {
		return group;
	}
	
	/**
	 * @param group
	 */
	public void setGroup(String group) {
		this.group = group;
	}
	
	/**
	 * @return
	 */
	public String getProject() {
		return project;
	}
	
	/**
	 * @param project
	 */
	public void setProject(String project) {
		this.project = project;
	}
	
	/**
	 * @return
	 */
	public String getCurrentState() {
		return currentState;
	}
	
	/**
	 * @param currentState
	 */
	public void setCurrentState(String currentState) {
		this.currentState = currentState;
	}
	
	/**
	 * @return
	 */
	public String getDistributionPath() {
		return distributionPath;
	}
	
	/**
	 * @param distributionPath
	 */
	public void setDistributionPath(String distributionPath) {
		this.distributionPath = distributionPath;
	}
	
	/**
	 * @return
	 */
	public String getRequestDate() {
		return requestDate;
	}
	
	/**
	 * @param requestDate
	 */
	public void setRequestDate(String requestDate) {
		this.requestDate = requestDate;
	}
	
	/**
	 * @return
	 */
	public String getApprovalDate() {
		return approvalDate;
	}
	
	/**
	 * @param approvalDate
	 */
	public void setApprovalDate(String approvalDate) {
		this.approvalDate = approvalDate;
	}
	
	/**
	 * @return
	 */
	public String getApprovedBy() {
		return approvedBy;
	}
	
	/**
	 * @param approvedBy
	 */
	public void setApprovedBy(String approvedBy) {
		this.approvedBy = approvedBy;
	}
	
	/**
	 * @return
	 */
	public String getCreationDate() {
		return creationDate;
	}
	
	/**
	 * @param creationDate
	 */
	public void setCreationDate(String creationDate) {
		this.creationDate = creationDate;
	}
	
	/**
	 * @return
	 */
	public DataLabels getLabels() {
		return labels;
	}
	
	/**
	 * @param labels
	 */
	public void setLabels(DataLabels labels) {
		this.labels = labels;
	}

	/**
	 * @return
	 */
	public String getKmfSig() {
		return kmfSig;
	}
	
	/**
	 * @param kmfSig
	 */
	public void setKmfSig(String kmfSig) {
		this.kmfSig = kmfSig;
	}

	/**
	 * @param stringValue
	 */
	public void setStringValue(String stringValue) {
		this.stringValue = stringValue;
	}

    public String toString()
    {
       return this.stringValue;
    }

}
