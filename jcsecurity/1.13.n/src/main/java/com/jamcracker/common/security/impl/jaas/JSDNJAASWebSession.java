/*
 * Class: JSDNJAASWebSession
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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.impl.AbstractUserWebSession;

/**
 * The web session implementation under the control of JAAS security framework.
 */
public class JSDNJAASWebSession extends AbstractUserWebSession {

	private static final long serialVersionUID = -874832056251726709L;
	protected HttpSession containerSession;
	protected Map<String, Object> propertyMap = new HashMap<String, Object>();

	public JSDNJAASWebSession(HttpServletRequest request,
			IJCAuthenticationToken authToken, Map<String, Object> propertyMap) {

		this.authToken = authToken;
		
	    for (Map.Entry<String, Object> entry : propertyMap.entrySet())
	    	this.propertyMap.put(entry.getKey(), entry.getValue());
		
		if(this.containerSession != null){
			containerSession.invalidate();
			request.getSession(true);
		}
		
		this.containerSession = request.getSession(true);
	
			
		/*  Commented below line which is not required since we have member variable "authToken" which holds the Authentication Token Information.
		 *  Use getAuthenticationToken() method which will return Authentication Token. 
		 */
		//this.containerSession.setAttribute(USER_AUTH_TOKEN, this.authToken);
		this.containerSession.setAttribute(JSDN_USER_WEB_SESSION, this);
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
		return "JSDNJAASWebSession@" + authToken;
	}
	
	public Map<String, Object> getSessionMap(){
		return this.propertyMap;
	}
}
