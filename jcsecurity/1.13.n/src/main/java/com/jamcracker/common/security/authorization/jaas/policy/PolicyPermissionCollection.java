/*
 * Class: PolicyPermissionCollection
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/policy/PolicyPermissionCollection.java>>
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

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.jamcracker.common.security.authorization.jaas.permissions.FieldAccessPermission;
import com.jamcracker.common.security.authorization.jaas.permissions.URLAccessPermission;

/**
 * The PolicyPermissionCollection acts as a container for different types of
 * permissions.
 */
public class PolicyPermissionCollection extends PermissionCollection {

	private static final long serialVersionUID = -7667043587320662937L;

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(PolicyPermissionCollection.class.getName());

	private Set<Permission> perms = new HashSet<Permission>();

	public void add(Permission perm) {
		perms.add(perm);
	}

	public void addAll(Set<Permission> permList) {

		if (permList != null) {
			perms.addAll(permList);
		}
	}

	public Enumeration<Permission> elements() {
		synchronized (this) {
			return Collections.enumeration(perms);
		}
	}

	public boolean implies(Permission permToCheck) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start implies() Method of PolicyPermissionCollection ");
		}
		if (permToCheck == null) {
			return false;
		}

		boolean implied = false;
		boolean impliedFlag = true;
		Enumeration<?> ele = elements();
		Permission curPerm;
		Object obj;

		while (ele.hasMoreElements()) {

			obj = ele.nextElement();

			/**
			 * Check with similar class of permissions only.
			 */
			if ((obj instanceof Permission)
					&& (permToCheck.getClass().equals(obj.getClass()))) {

				curPerm = (Permission) obj;
				LOGGER.debug(">>>> Checking " + curPerm);

				if (curPerm.implies(permToCheck)) {
					implied = true;
					impliedFlag = false;
					break;
				}
			}
			
		}
		if(permToCheck.getClass().equals(FieldAccessPermission.class))
		{
			if(impliedFlag)
				implied = true;
			else
				implied = false;
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" end implies() Method of PolicyPermissionCollection ");
		}
		return implied;
	}

}
