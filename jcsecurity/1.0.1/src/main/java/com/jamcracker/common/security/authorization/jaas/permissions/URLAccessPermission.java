/*
 * Class: URLAccessPermission
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/permissions/URLAccessPermission.java>>
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
package com.jamcracker.common.security.authorization.jaas.permissions;

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;

import com.jamcracker.common.security.authorization.ResourceActionType;

/**
 * URL access permission
 */
public class URLAccessPermission extends AbstractPermission {

	private static final long serialVersionUID = 6921770164964303317L;

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(URLAccessPermission.class.getName());

	private static final String PATTERN_ALL = "*";

	public URLAccessPermission(String url,String dynamicPermissionClassName) {
		this(url, ResourceActionType.URL_ACCESS.getActionType(),dynamicPermissionClassName);
	}

	/**
	 * The constructor calling is based on the number of args passed in policy
	 * (struts.policy)
	 * 
	 * @param eventName
	 * @param action
	 */
	public URLAccessPermission(String url, String action,String dynamicPermissionClassName) {
		super(url, action,dynamicPermissionClassName);
		LOGGER.debug("Permission instantiated : " + this);
	}

	public String toString() {
		return "URLAccessPermission { " + getName() + ", " + getActions()
				+ " }";
	}

	public boolean implies(Permission otherPermission) {
		boolean returnFlag = false;
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start implies() Method of URLAccessPermission ");
		}
		LOGGER.debug("self = " + this + " checking for otherPermission = "
				+ otherPermission);

		if (otherPermission instanceof URLAccessPermission) {

			/**
			 * If the current permission is a pattern instead of a some hard
			 * coded URL
			 * 
			 * Ex: /common/security/*
			 */
			String patternToMatch = this.getName();

			if (patternToMatch.endsWith(PATTERN_ALL)) {
				patternToMatch = patternToMatch.substring(0, patternToMatch
						.lastIndexOf(PATTERN_ALL));
			}
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Checking pattern matching with : "
						+ patternToMatch);
			}
			returnFlag= otherPermission.getName().startsWith(patternToMatch);
			if(returnFlag)
				returnFlag=executeDyamicPermission(otherPermission);
	
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end implies() Method of URLAccessPermission ");
		}
		return returnFlag;
	}

	public PermissionCollection newPermissionCollection() {
		return super.newPermissionCollection();
	}

}
