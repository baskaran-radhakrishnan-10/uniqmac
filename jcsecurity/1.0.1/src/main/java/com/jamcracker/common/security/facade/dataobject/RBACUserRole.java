/*
 * Class: RBACUserRole
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  29/12/2010   Rajesh Rangeneni 	1.0			Initial version
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
package com.jamcracker.common.security.facade.dataobject;

/**
 * This class represents the RBAC User role. 
 */
public class RBACUserRole implements java.io.Serializable {
	
	private static final long serialVersionUID = 9178942401519323068L;
	private String roleName = null;

	public String getRoleName() {
		return roleName;
	}

	public void setRoleName(String roleName) {
		this.roleName = roleName;
	}

	public int getRoleId() {
		return roleId;
	}

	public void setRoleId(int roleId) {
		this.roleId = roleId;
	}

	private int roleId;

	public RBACUserRole(int roleId, String roleName) {
		this.roleId = roleId;
		this.roleName = roleName;
	}

	public RBACUserRole() {
	}
	public String toString() {
		return this.roleName;
	}
}
