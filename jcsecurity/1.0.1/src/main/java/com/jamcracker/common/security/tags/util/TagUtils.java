/*
 * Class: TagUtils
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   --------------     -------     ---------------------------------------
 * 1.0  10/03/2010   Rajesh Kr. Jha		1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/common/tags/util/TagUtils.java>>
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 ******************************************************/

package com.jamcracker.common.security.tags.util;

import javax.servlet.http.HttpServletRequest;

public class TagUtils {
	
	public static final String CONTEXT_PATH_SEPARATOR = "/";
	public static final String VOID_JS = "javascript:void(0)";
	public static final String ACTION_SUFFIX = ".action";
	
	//==============
	public static String getContextAppendedPath(String url, HttpServletRequest request) {
		
		if (request == null) {
			return url;
		}
		
		return maskDoubleSlashes((request.getContextPath() + CONTEXT_PATH_SEPARATOR + url));
	}
	
	public static String getContextRelativePath(String url, HttpServletRequest request) {
		
		if (request == null) {
			return url;
		}
		
		return getContextRelativePath(url, request.getContextPath());
	}
	
	/**
	 * To get the required relative path.
	 * 
	 * @param url RequestURI
	 * @param context contextPath
	 * @return ContextRelativePath
	 */
	public static String getContextRelativePath(String url, String context) {
		
		if (null != url && null != context) {
			
			/**
			 * Remove double slashes.
			 * Ex : /tsmarketplace/login//doLogOut.action to
			 * to   /tsmarketplace/login/doLogOut.action
			 *   
			 */
			url = maskDoubleSlashes(url);
			
			String [] pathArr = url.split(context);
			return pathArr.length > 1 ? pathArr[1] : url;
		}
		
		return url;
	}
	
	/**
	 * Remove double slashes.
	 * Ex : /tsmarketplace/login//doLogOut.action to
	 * to   /tsmarketplace/login/doLogOut.action
	 *   
	 */
	private static String maskDoubleSlashes(String url) {
		return url.replaceAll("//", "/");
	}
	
	
	/**
	 * This method returns action URL prefixed with context path.
	 * If the action url is not valid then it returns void JS
	 * which avoids rendering unwanted URLs. 
	 * 
	 * @param request
	 * @param actionURL
	 * @return
	 */
	public static String getActionLink(HttpServletRequest request, String actionURL) {
		
		String hrefLink = null;
		
		if (actionURL == null || 
				actionURL.trim().length() == 0 || 
					!actionURL.endsWith(ACTION_SUFFIX)) {			
			hrefLink = VOID_JS;
		} else {
			
			if (actionURL.startsWith(CONTEXT_PATH_SEPARATOR) ||
					request.getContextPath().endsWith(CONTEXT_PATH_SEPARATOR)) {
				hrefLink = (request.getContextPath() + actionURL);
			} else {
				hrefLink = (request.getContextPath() + CONTEXT_PATH_SEPARATOR + actionURL);
			}
		}
		
		return hrefLink;
	}
}
