/*
 * Class: PermissionAdapter
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/policy/PermissionAdapter.java>>
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

import java.security.CodeSource;
import java.security.PermissionCollection;
import java.security.ProtectionDomain;

/**
 * 
 * The PermissionAdapter is useful to get the permissions associated with code
 * source or protection domain. The custom policy deligates the responsibility
 * of fetching permissions to policy adapter.
 */
public interface PermissionAdapter {
	public PermissionCollection getPermissions(CodeSource codeSource);

	public PermissionCollection getPermissions(ProtectionDomain domain);
	
	public void removeActorPermission(int companyID);
}
