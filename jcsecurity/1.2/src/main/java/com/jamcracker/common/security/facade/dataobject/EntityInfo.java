/*
 * Class: EntityInfo
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  21/10/2011   Akshay Tigga 	      1.0		EntityInfo is a storehouse for adding the entities and fetching the entities	    
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

import java.util.ArrayList;
import java.util.List;

public class EntityInfo {
	/**
	 * Contains a list of Entity
	 */
	private List<Entity> entityList = new ArrayList<Entity>();

	private EntityInfo(){
		
	}
	public static EntityInfo getInstance(){
		return new EntityInfo();
	}
	public List<Entity> getEntityList() {
		return this.entityList;
	}
	
	public void addEntity(int entityId){
		Entity entity = new Entity();
		entity.setEntityId(entityId);
		this.entityList.add(entity);
	}

}
