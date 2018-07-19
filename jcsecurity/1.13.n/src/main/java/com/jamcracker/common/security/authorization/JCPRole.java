/*
 * Class: JCPRole
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/JCPRole.java>>
 * 2.0	31/03/2010	 Rajesh/Shireesh	1.0			Added ACLRole.
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 ******************************************************/
package com.jamcracker.common.security.authorization;

import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * JCP user roles.
 */
public class JCPRole implements Serializable {

	private static final long serialVersionUID = 1L;

	private Integer roleId;
	
	private int aclRoleId;
	
	private String roleType;

	private String status;

	private Date startActiveDate;

	private Date endActiveDate;

	private Date creationDate;

	private int createdBy;

	private Date updateDate;

	private int updatedBy;

	private Set<JCPPrivilege> privileges = new HashSet<JCPPrivilege>(0);

	/**
	 * @return the privileges
	 */
	public Set<JCPPrivilege> getPrivileges() {
		return privileges;
	}

	/**
	 * @param privileges
	 *            the privileges to set
	 */
	public void setPrivileges(Set<JCPPrivilege> privileges) {
		this.privileges = privileges;
	}

	/**
	 * @return the roleId
	 */
	public Integer getRoleId() {
		return roleId;
	}

	/**
	 * @param roleId
	 *            the roleId to set
	 */
	public void setRoleId(Integer roleId) {
		this.roleId = roleId;
	}
	
	

	/**
	 * @return the aCLRoleId
	 */
	public int getACLRoleId() {
		return aclRoleId;
	}

	/**
	 * @param roleId the aCLRoleId to set
	 */
	public void setACLRoleId(int aclRoleId) {
		this.aclRoleId = aclRoleId;
	}

	/**
	 * @return the roleType
	 */
	public String getRoleType() {
		return roleType;
	}

	/**
	 * @param roleType
	 *            the roleType to set
	 */
	public void setRoleType(String roleType) {
		this.roleType = roleType;
	}

	/**
	 * @return the status
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * @param status
	 *            the status to set
	 */
	public void setStatus(String status) {
		this.status = status;
	}

	/**
	 * @return the startActiveDate
	 */
	public Date getStartActiveDate() {
		return startActiveDate;
	}

	/**
	 * @param startActiveDate
	 *            the startActiveDate to set
	 */
	public void setStartActiveDate(Date startActiveDate) {
		this.startActiveDate = startActiveDate;
	}

	/**
	 * @return the endActiveDate
	 */
	public Date getEndActiveDate() {
		return endActiveDate;
	}

	/**
	 * @param endActiveDate
	 *            the endActiveDate to set
	 */
	public void setEndActiveDate(Date endActiveDate) {
		this.endActiveDate = endActiveDate;
	}

	/**
	 * @return the creationDate
	 */
	public Date getCreationDate() {
		return creationDate;
	}

	/**
	 * @param creationDate
	 *            the creationDate to set
	 */
	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	/**
	 * @return the createdBy
	 */
	public int getCreatedBy() {
		return createdBy;
	}

	/**
	 * @param createdBy
	 *            the createdBy to set
	 */
	public void setCreatedBy(int createdBy) {
		this.createdBy = createdBy;
	}

	/**
	 * @return the updateDate
	 */
	public Date getUpdateDate() {
		return updateDate;
	}

	/**
	 * @param updateDate
	 *            the updateDate to set
	 */
	public void setUpdateDate(Date updateDate) {
		this.updateDate = updateDate;
	}

	/**
	 * @return the updatedBy
	 */
	public int getUpdatedBy() {
		return updatedBy;
	}

	/**
	 * @param updatedBy
	 *            the updatedBy to set
	 */
	public void setUpdatedBy(int updatedBy) {
		this.updatedBy = updatedBy;
	}
}
