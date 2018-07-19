/*
 * Class: ResourceActionType
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/ResourceActionType.java>>
 * 2.0  04/03/2010   Nisha              1.0         Added for menu rendering 
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

/**
 * This class hold different types of actions associated with differnt
 * resources.
 */
public final class ResourceActionType {

	/**
	 * The URL access action.
	 */
	public static final ResourceActionType URL_ACCESS = new ResourceActionType(
			"access");

	/**
	 * The event/api execute action.
	 */
	public static final ResourceActionType EVENT_EXECUTE = new ResourceActionType(
			"execute");
	public static final ResourceActionType EVENT_MASK = new ResourceActionType(
			"mask");

	/**
	 * The JSP page field view/edit actions.
	 */
	public static final ResourceActionType FIELD_VIEW = new ResourceActionType(
			"view");
	public static final ResourceActionType FIELD_EDIT = new ResourceActionType(
			"edit");
	
	public static final ResourceActionType MENU_VIEW = new ResourceActionType(
	        "menu");

	public static final ResourceActionType WIDGET_ACCESS = new ResourceActionType(
	"widgetaccess");
	
	private String actionType;

	private ResourceActionType(String actionType) {
		this.actionType = actionType;
	}

	public String getActionType() {
		return actionType;
	}

	public void setActionType(String actionType) {
		this.actionType = actionType;
	}

	public boolean equals(Object other) {

		if (other instanceof ResourceActionType) {
			return this.actionType
					.equals(((ResourceActionType) other).actionType);
		}

		return false;
	}

	public String toString() {
		return "ResourceActionType {" + this.actionType + "}";
	}
}
