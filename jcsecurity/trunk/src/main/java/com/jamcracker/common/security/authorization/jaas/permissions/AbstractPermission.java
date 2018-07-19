/*
 * Class: AbstractPermission
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/permissions/AbstractPermission.java>>
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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.BasicPermission;
import java.security.Permission;
import java.util.Map;

import com.jamcracker.common.exception.JCBaseRunTimeException;
import com.jamcracker.event.common.IEvent;

public abstract class AbstractPermission extends BasicPermission {

	private static final long serialVersionUID = 3888187170316644712L;
	protected String actions;
	protected Map<String, Object> userContextMap ;
	protected String dynamicPermissionClassName ;
	protected String eventName;
	protected IEvent event;
	
	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
	.getLogger(AbstractPermission.class.getName());
	
	/**
	 * This constructor needs to be used while loading the permission from DBPermissionAdapter
	 * @param name
	 * @param actions
	 * @param dynamicPermissionClassName
	 * @see DBPermissionAdapter{@loadPermission}
	 */
	public AbstractPermission(String name, String actions,String dynamicPermissionClassName) {
		super(name);
		this.actions = actions;
		this.dynamicPermissionClassName=dynamicPermissionClassName;
		this.eventName = name;
	}
	
	public AbstractPermission(String name, String actions) {
		super(name);
		this.actions = actions;
	}
	/**
	 * This constructor needs to be used in JAASSecurityPrivider when an event is being accessed from application
	 * @param event
	 * @param action
	 * @see JAASSecurityProvider{@canAccessEvent}
	 */
	public AbstractPermission(IEvent event, String action){
		super(event.getEventName());
		this.event = event;
		this.actions = action;
	}
	
	public String getDynamicPermissionClassName() {
		return dynamicPermissionClassName;
	}

	public void setDynamicPermissionClassName(String dynamicPermissionClassName) {
		this.dynamicPermissionClassName = dynamicPermissionClassName;
	}

	public String getActions() {
		return this.actions;
	}

	public void setActions(String actions) {
		this.actions = actions;
	}
	public Map<String, Object> getUserContextMap() {
		return this.userContextMap;
	}
	
	public void setUserContextMap(Map<String, Object> userContextMap) {
		this.userContextMap = userContextMap;
	}
	
	public String getEventName() {
		return eventName;
	}
	public void setEventName(String eventName) {
		this.eventName = eventName;
	}
	
	public IEvent getEvent() {
		return event;
	}

	public void setEvent(IEvent event) {
		this.event = event;
	}

	@Deprecated
	public boolean executeDyamicPermission(Permission otherPermission) {
			boolean permissionGranted = true;
			String className = ((AbstractPermission) otherPermission).getDynamicPermissionClassName();
			if( className!= null && !"".equals(className)){
				 try {
					Class dynamicClass = Class.forName(className);
					Class parameterTypes[] = {AbstractPermission.class,Map.class};
					Method method=dynamicClass.getMethod("implies",parameterTypes);
					Object dynamicObject = dynamicClass.newInstance();
					Object arglist[] ={otherPermission,userContextMap};
			     	Object retobj = method.invoke(dynamicObject,arglist );
			     	Boolean returnBooleanObj=(Boolean)retobj;
			     	return returnBooleanObj.booleanValue();
				}  catch (ClassNotFoundException e) {
					LOGGER.error("Getting entity permission failed because ClassNotFoundException occured : " , e);
				}
				catch (NoSuchMethodException e) {
					LOGGER.error("Getting entity permission failed because NoSuchMethodException occured : " , e);
				}
				catch (IllegalAccessException e) {
					LOGGER.error("Getting entity permission failed because IllegalAccessException occured : " , e);
				}
				catch (InstantiationException e) {
					LOGGER.error("Getting entity permission failed because InstantiationException occured : " , e);
				}
				catch (InvocationTargetException e) {
					LOGGER.error("Getting entity permission failed because InvocationTargetException occured : " , e);
				}
			}
			return permissionGranted;
	}
	/**
	 * Returns the dynamic permission associated with an event
	 * @param otherPermission
	 * @param requestedEventPermission
	 * @return boolean
	 */
	public boolean executeDyamicPermission(Permission otherPermission,Permission requestedEventPermission) {
		boolean permissionGranted = true;
		AbstractPermission dynamicPerm = (AbstractPermission) otherPermission;
		String className = dynamicPerm.getDynamicPermissionClassName();
		AbstractPermission reqPermission = (AbstractPermission) requestedEventPermission;
		if( className!= null && !"".equals(className)){
			 try {
				Class<?> dynamicClass = Class.forName(className);
				Constructor<?> constructor = dynamicClass.getConstructor();
				Class parameterTypes[] = {AbstractPermission.class,Map.class};
				Method method=dynamicClass.getMethod("implies",parameterTypes);
				Object dynamicObject = constructor.newInstance();
				Object arglist[] ={reqPermission,reqPermission.getUserContextMap()};
		     	Object retobj = method.invoke(dynamicObject,arglist );
		     	Boolean returnBooleanObj=(Boolean)retobj;
		     	permissionGranted = returnBooleanObj.booleanValue();
			} catch (ClassNotFoundException e) {
				permissionGranted=false;
				LOGGER.error("Getting entity permission failed because ClassNotFoundException occured : " , e);
			}
			catch (NoSuchMethodException e) {
				permissionGranted=false;
				LOGGER.error("Getting entity permission failed because NoSuchMethodException occured : " , e);
			}
			catch (IllegalAccessException e) {
				permissionGranted=false;
				LOGGER.error("Getting entity permission failed because IllegalAccessException occured : " , e);
			}
			catch (InstantiationException e) {
				permissionGranted=false;
				LOGGER.error("Getting entity permission failed because InstantiationException occured : " , e);
			}
			catch (InvocationTargetException e) {
				permissionGranted=false;
				 if(e.getTargetException() instanceof JCBaseRunTimeException ){
					JCBaseRunTimeException ex = (JCBaseRunTimeException)e.getTargetException();
					permissionGranted=false;
					throw ex;
				    }	
				LOGGER.error("Getting entity permission failed because InvocationTargetException occured : " , e);
			}
		}
		return permissionGranted;
}
	

}
