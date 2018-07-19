/*
 * Class: EventAccessPermission
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/permissions/EventAccessPermission.java>>
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

import com.jamcracker.event.common.IEvent;

/**
 * Event access permission
 */
public class EventAccessPermission extends AbstractPermission {

	private static final long serialVersionUID = -7919479887149987275L;

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(EventAccessPermission.class.getName());

	/**
	 * The constructor calling is based on the number of args passed in policy
	 * (struts.policy)
	 * 
	 * @param eventName
	 * @param action
	 */
	
	public EventAccessPermission(String eventName, String action,String dynamicPermissionClassName) {
		super(eventName, action,dynamicPermissionClassName);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Permission instantiated :: " + this);
		}
	}
	
	public EventAccessPermission(IEvent event, String action){
		super(event,action);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Permission instantiated for event :: " + event.getEventName());
		}
	}
	
	public String toString() {
		return "EventAccessPermission { " + getName() + ", " + getActions()
				+ " }";
	}

	public boolean implies(Permission otherPermission) {
		boolean returnFlag = false;
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start implies() Method of EventAccessPermission ");
		}
		LOGGER.debug("self = " + this + " checking for otherPermission = "
				+ otherPermission);

		if (otherPermission instanceof EventAccessPermission) {

			returnFlag= otherPermission.getName().equals(this.getName())
					&& otherPermission.getActions().equals(this.getActions());
			
			if(returnFlag)
				returnFlag=executeDyamicPermission(this,otherPermission);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end implies() Method of EventAccessPermission ");
		}
		return returnFlag;
	}

	public PermissionCollection newPermissionCollection() {
		return super.newPermissionCollection();
	}

}
