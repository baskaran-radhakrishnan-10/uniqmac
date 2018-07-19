/*
 * Class: ResourceConfig
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/ResourceConfig.java>>
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

import java.util.HashMap;
import java.util.Map;

/**
 * This class represents the actual resource configuration which include
 * resource type and some resource specific properties.
 */
public class ResourceConfig {

	private ResourceType resourceType;
	private ResourceActionType resourceActionType;
	private Map<String, Object> resourceProperties = new HashMap<String, Object>();

	public static final String URL_TO_ACCESS = "URL_TO_ACCESS";
	public static final String EVENT_TO_ACCESS = "EVENT_TO_ACCESS";

	public static final String JSP_URI_TO_ACCESS = "JSP_URI_TO_ACCESS";
	public static final String FIELD_TO_ACCESS = "FIELD_TO_ACCESS";
	public static final String MENU_TO_ACCESS = "MENU_TO_ACCESS";
	public static final String WIDGET_TO_ACCESS = "WIDGET_TO_ACCESS";
	

	public ResourceConfig(ResourceType resourceType,
			ResourceActionType resourceActionType) {
		super();
		this.resourceType = resourceType;
		this.resourceActionType = resourceActionType;
	}

	public ResourceActionType getResourceActionType() {
		return resourceActionType;
	}

	public void setResourceActionType(ResourceActionType resourceActionType) {
		this.resourceActionType = resourceActionType;
	}

	public ResourceType getResourceType() {
		return resourceType;
	}

	public void setResourceType(ResourceType resourceType) {
		this.resourceType = resourceType;
	}

	public Object getResourceProperty(String key) {
		return resourceProperties.get(key);
	}

	public void setResourceProperty(String key, Object value) {
		this.resourceProperties.put(key, value);
	}

}
