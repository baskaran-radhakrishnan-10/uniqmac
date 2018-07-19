/*
 * Class: Entity
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  21/10/2011   Akshay Tigga 	     1.0	    Entity data access object is container for information related to an entity in JCP_ROLE_ENTITY_MAPPING table		    
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
package com.jamcracker.common.security.facade.dataobject;
/**
 * Data Access Object to house entity information
 * @author atigga
 *
 */
public class Entity {
	/**
	 * Role having permission for entity
	 */
	private int roleId;
	/**
	 * Unique entityId corresponding to entity (can be offer/location etc)
	 */
	private int entityId;
	/**
	 * Entity type
	 * OFFER 'O'
	 */
	private String entityType;
	/**
	 * Permission Status 'A' or 'D'
	 */
	private String status;

	public int getEntityId() {
		return entityId;
	}

	public void setEntityId(int entityId) {
		this.entityId = entityId;
	}

	public int getRoleId() {
		return roleId;
	}

	public void setRoleId(int roleId) {
		this.roleId = roleId;
	}

	public String getEntityType() {
		return entityType;
	}

	public void setEntityType(String entityType) {
		this.entityType = entityType;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}
	
	@Override
	public String toString() {
		
		return "roleId = " + roleId + " entityId = " + entityId + " entityType = "+entityType; 
	}

}
