/*
 * Class: ResourceType
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/ResourceType.java>>
 * 2.0  04/03/2010   Nisha			    1.0	        Added for menu rendering
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
 * This class represents different types of resources we are going to access
 * with in the system.
 */
public class ResourceType {

	/**
	 * The URL resources.
	 */
	public static final ResourceType URL_RESOURCE = new ResourceType("URL");

	/**
	 * The event resources.
	 */
	public static final ResourceType EVENT_RESOURCE = new ResourceType("EVENT");

	/**
	 * The JSP page field resources.
	 */
	public static final ResourceType FIELD_RESOURCE = new ResourceType("FIELD");
	/**
	 * The Menu resources
	 */
	public static final ResourceType MENU_RESOURCE = new ResourceType("MENU");
	
	/**
	 * The Widget resources
	 */
	public static final ResourceType WIDGET_RESOURCE = new ResourceType("WIDGET");

	private String resourceType;

	protected ResourceType(String resourceType) {
		this.resourceType = resourceType;
	}

	public boolean equals(Object other) {

		if (other instanceof ResourceType) {
			return this.resourceType
					.equals(((ResourceType) other).resourceType);
		}

		return false;
	}

	public String toString() {
		return "ResourceType {" + this.resourceType + "}";
	}
}
