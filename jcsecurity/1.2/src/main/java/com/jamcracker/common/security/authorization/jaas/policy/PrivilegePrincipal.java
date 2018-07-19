/*
 * Class: PrivilegePrincipal
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/policy/PrivilegePrincipal.java>>
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
package com.jamcracker.common.security.authorization.jaas.policy;

import java.security.Principal;

/**
 * This class represents a privilege assigned to a authenticated user. Once the
 * user is authenticated a list of privileges assigned as a list of
 * PrivilegePrincipal objects.
 */
public class PrivilegePrincipal implements Principal, java.io.Serializable {

	
	private static final long serialVersionUID = -6631137018500147295L;
	private String privilegeName;
	private String instanceId;
	private int privilegeId;

	public PrivilegePrincipal(int privilegeId, String privilegeName,int companyId) {
		this.privilegeId = privilegeId;
		this.privilegeName = privilegeName;
		this.companyId = companyId;
	}
	
	public PrivilegePrincipal(int privilegeId, String privilegeName,int companyId,String instanceId) {
		this.privilegeId = privilegeId;
		this.privilegeName = privilegeName;
		this.companyId = companyId;
		this.instanceId = instanceId;
	}
	private int companyId;
	
	public int getCompanyId() {
		return companyId;
	}

	public void setCompanyId(int companyId) {
		this.companyId = companyId;
	}
	public String getInstanceId() {
		return instanceId;
	}

	public void setInstanceId(String instanceId) {
		this.instanceId = instanceId;
	}
	public PrivilegePrincipal(String privilegeName) {
		this.privilegeName = privilegeName;
	}

	public int getPrivilegeId() {
		return privilegeId;
	}

	public void setPrivilegeId(int privilegeId) {
		this.privilegeId = privilegeId;
	}

	public String getName() {
		return this.privilegeName;
	}

	public String toString() {
		return PrivilegePrincipal.class + "@" + getName()+":companyId::"+getCompanyId()+" :privilegeId ::"+getPrivilegeId();
	}
}
