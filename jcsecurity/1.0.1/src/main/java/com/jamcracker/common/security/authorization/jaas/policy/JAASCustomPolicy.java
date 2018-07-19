/*
 * Class: JAASCustomPolicy
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/policy/JAASCustomPolicy.java>>
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
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.Enumeration;

import com.jamcracker.common.security.impl.jaas.JAASSecurityProvider;

/**
 * The JAASCustomPolicy acts as policy provider for the application. It keeps an
 * internal reference to already installed policy and merges the permissions
 * from this policy and existing policy.
 */
public class JAASCustomPolicy extends Policy {
	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(JAASCustomPolicy.class.getName());
	private static final Policy DEFAULT_POLICY = new sun.security.provider.PolicyFile();
	private PermissionAdapter permissionAdapter = DBPermissionAdapter
			.getInstance();
	private Policy instlledPolicy = DEFAULT_POLICY;

	public JAASCustomPolicy() {
		this(DEFAULT_POLICY);
	}

	public JAASCustomPolicy(Policy existingPolicy) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" existing Policy is " + existingPolicy);
		}
		if (existingPolicy != null) {
			instlledPolicy = DEFAULT_POLICY;
		}
	}

	public PermissionCollection getPermissions(CodeSource codeSource) {

		/**
		 * We will check only the permissions associated with roles so nothing
		 * to do here.
		 */
		return instlledPolicy.getPermissions(codeSource);
	}

	public PermissionCollection getPermissions(ProtectionDomain domain) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start getPermissions() Method of JAASCustomPolicy ");
		}
		PermissionCollection exPerrmissionCollection = instlledPolicy
				.getPermissions(domain);

		PermissionCollection permissionCollection = permissionAdapter
				.getPermissions(domain);

		Enumeration<?> ele = exPerrmissionCollection.elements();
		Permission permission;
		Object obj;

		while (ele.hasMoreElements()) {

			obj = ele.nextElement();

			if (obj instanceof Permission) {
				permission = (Permission) obj;
				permissionCollection.add(permission);
			}
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END getPermissions() Method of JAASCustomPolicy ");
		}
		return permissionCollection;
	}

	public void refresh() {
		// As we set our own custom policy and JBOSS is also
		// trying to refresh the policy, this call may happen
		// randomly. So we will load all permissions
		// during startup.
		// If we need to reload permissions
		// we will do that through permissionAdapter.refresh()
		// as part of separate call and not through
		// JAASCustomPolicy.refresh.

		// instlledPolicy.refresh();
		// permissionAdapter.refresh();
	}

}
