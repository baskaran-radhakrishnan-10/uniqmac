/*
 * Class: PrincipalPermissionConfig
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/policy/PrincipalPermissionConfig.java>>
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

/**
 * The class hold the information about a particular permission and the
 * principle information to which it is associated.
 */
public class PrincipalPermissionConfig implements java.io.Serializable {

	private static final long serialVersionUID = -5823008582720209058L;
	private int principalId;
	private int resourceId;

	private String principalName;
	private int resourceType;
	private String resourceTypeName;
	private String resourcePermissionClass;
	private String resourceName;
	private String resourceAction;

	private String dynamicPermissionClassName ;

	public String getDynamicPermissionClassName() {
		return dynamicPermissionClassName;
	}

	public void setDynamicPermissionClassName(String dynamicPermissionClassName) {
		this.dynamicPermissionClassName = dynamicPermissionClassName;
	}
	public int getPrincipalId() {
		return principalId;
	}

	public void setPrincipalId(int principalId) {
		this.principalId = principalId;
	}

	public int getResourceId() {
		return resourceId;
	}

	public void setResourceId(int resourceId) {
		this.resourceId = resourceId;
	}

	public String getPrincipalName() {
		return principalName;
	}

	public void setPrincipalName(String principalName) {
		this.principalName = principalName;
	}

	public int getResourceType() {
		return resourceType;
	}

	public void setResourceType(int resourceType) {
		this.resourceType = resourceType;
	}

	public String getResourceTypeName() {
		return resourceTypeName;
	}

	public void setResourceTypeName(String resourceTypeName) {
		this.resourceTypeName = resourceTypeName;
	}

	public String getResourcePermissionClass() {
		return resourcePermissionClass;
	}

	public void setResourcePermissionClass(String resourcePermissionClass) {
		this.resourcePermissionClass = resourcePermissionClass;
	}

	public String getResourceName() {
		return resourceName;
	}

	public void setResourceName(String resourceName) {
		this.resourceName = resourceName;
	}

	public String getResourceAction() {
		return resourceAction;
	}

	public void setResourceAction(String resourceAction) {
		this.resourceAction = resourceAction;
	}

	public String toString() {

		StringBuilder sb = new StringBuilder("PrincipalPermissionConfig { ");
		sb.append("principalName = ").append(principalName);
		sb.append(", resourceTypeName = ").append(resourceTypeName);
		sb.append(", resourcePermissionClass = ").append(
				resourcePermissionClass);
		sb.append(", resourceName = ").append(resourceName);
		sb.append(", resourceAction = ").append(resourceAction);
		return sb.append(" }").toString();
	}
}
