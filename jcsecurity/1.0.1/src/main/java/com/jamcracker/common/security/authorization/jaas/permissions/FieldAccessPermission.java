/*
 * Class: FieldAccessPermission
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/permissions/FieldAccessPermission.java>>
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

import java.security.BasicPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;

/**
 * Field access permission
 */
public class FieldAccessPermission extends AbstractPermission {

	private static final long serialVersionUID = -7156186674171487802L;

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(FieldAccessPermission.class.getName());

	private static final String PAGE_FIELD_SEPARATOR = "@";

	public FieldAccessPermission(String jspURI_fieldName, String accessType,String dynamicPermissionClassName) {
		super(jspURI_fieldName, accessType,dynamicPermissionClassName);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Permission instantiated : " + this);
		}
	}

	public FieldAccessPermission(String jspURI, String fieldName,
			String accessType,String dynamicPermissionClassName) {
		this(jspURI + PAGE_FIELD_SEPARATOR + fieldName, accessType,dynamicPermissionClassName);
	}

	public String toString() {
		return "FieldAccessPermission { " + getName() + ", " + getActions()
				+ " }";
	}

	public boolean implies(Permission otherPermission) {
		boolean returnFlag = false;
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start implies() Method of FieldAccessPermission ");
		}
		LOGGER.debug("self = " + this + " checking for otherPermission = "
				+ otherPermission);

		if (otherPermission instanceof FieldAccessPermission) {
			if(otherPermission.getName().equals(this.getName()))
			{
				returnFlag=  otherPermission.getActions().equals(this.getActions());
				if(returnFlag)
					returnFlag=executeDyamicPermission(otherPermission);
		
			}
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end implies() Method of FieldAccessPermission ");
		}
		return returnFlag;
	}

	public PermissionCollection newPermissionCollection() {
		return super.newPermissionCollection();
	}

}
