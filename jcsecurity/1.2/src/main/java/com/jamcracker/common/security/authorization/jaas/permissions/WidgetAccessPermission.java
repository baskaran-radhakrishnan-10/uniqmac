/*
 * Class: WidgetAccessPermission
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  17/01/2011   Rajesh Rangeneni	1.0			Added for content module to control widget access.
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

/**
 * Widget access permission
 */
public class WidgetAccessPermission extends AbstractPermission {

	private static final long serialVersionUID = -8105547599276597208L;

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(WidgetAccessPermission.class.getName());

	/**
	 * The constructor calling is based on the number of args passed in policy
	 * (struts.policy)
	 * 
	 * @param widgetId
	 * @param action
	 */
	public WidgetAccessPermission(String widgetId, String action,String dynamicPermissionClassName) {
		super(widgetId, action,dynamicPermissionClassName);
			LOGGER.debug("Permission instantiated :: " + this);
	}

	public String toString() {
		return "WidgetAccessPermission { " + getName() + ", " + getActions()
				+ " }";
	}

	public boolean implies(Permission otherPermission) {
		boolean returnFlag = false;
			LOGGER.debug(" start implies() Method of WidgetAccessPermission ");
		LOGGER.debug("self = " + this + " checking for otherPermission = "
				+ otherPermission);

		if (otherPermission instanceof WidgetAccessPermission) {

			returnFlag= otherPermission.getName().equals(this.getName())
					&& otherPermission.getActions().equals(this.getActions());
			
			if(returnFlag)
				returnFlag=executeDyamicPermission(otherPermission);
		}
		LOGGER.debug(" end implies() Method of WidgetAccessPermission ");
		return returnFlag;
	}

	public PermissionCollection newPermissionCollection() {
		return super.newPermissionCollection();
	}

}
