/*
 * Class: CloudJAASWebSession
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  11/02/2011   Rajesh Rangeneni	1.0			
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
package com.jamcracker.common.security.impl.jaas;

import java.util.Hashtable;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.jamcracker.common.security.authentication.AuthToken;
import com.jamcracker.common.security.impl.AbstractUserWebSession;

public class AppJAASWebSession extends AbstractUserWebSession {

	private static final long serialVersionUID = 4509550906678355612L;
	protected HttpSession containerSession;
	protected Map<String, Object> propertyMap = new Hashtable<String, Object>();
	
	public AppJAASWebSession(HttpServletRequest request,
			AuthToken authToken, Map<String, Object> propertyMap) {
		this.authToken = authToken;
		this.propertyMap = propertyMap;
		
		if(this.containerSession != null){
			containerSession.invalidate();
			request.getSession(true);
		}
		
		this.containerSession = request.getSession(true);
			
		this.containerSession.setAttribute(APP_USER_WEB_SESSION, this);
	}
	
	

	@Override
	public HttpSession getContainerSession() {
		return this.containerSession;
	}

	@Override
	public Object getProperty(String key) {
		return this.propertyMap.get(key);
	}

	@Override
	public void setProperty(String key, Object value) {
		this.propertyMap.put(key, value);
	}

	public String toString() {
		return "JAASWebSession@" + authToken;
	}
	
	public Map<String, Object> getSessionMap(){
		return this.propertyMap;
	}
}
