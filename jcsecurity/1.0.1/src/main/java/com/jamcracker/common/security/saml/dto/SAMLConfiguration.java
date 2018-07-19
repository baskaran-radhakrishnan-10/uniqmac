/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.dto.SAMLConfiguration
 * @version 1.0
 * @author 
 * @see
 *
 * This holds the SAML Configuration information for user authentication.
 * 
 ******************************************************/


package com.jamcracker.common.security.saml.dto;

import java.util.HashMap;
import java.util.Map;

public class SAMLConfiguration {
	
	Map<String, Object> configMap = new HashMap<String, Object>();
	
	public void setConfigValue(String key, Object value){
		configMap.put(key, value);
	}
	
	public Object getConfigValue(String key){
		return configMap.get(key);
	}
}
