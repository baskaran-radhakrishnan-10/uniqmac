/*
 * Class: AuthenticationInfo
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/AuthInfo.java>>
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
package com.jamcracker.common.security.authentication;

import java.util.HashMap;
import java.util.Map;

import com.jamcracker.common.security.ClientType;
import com.jamcracker.common.security.authentication.jaas.JAASConstants;

/**
 * The class holds authentication information that has to be validated by
 * authentication provider.
 */
public class AuthenticationInfo implements java.io.Serializable {
	
	Map<String, Object> infoMap = new HashMap<String, Object>();
	public static final String CLIENT_TYPE = "clientType";

	private static final long serialVersionUID = 2643258116672044004L;
	
	
	/**
	 * @return the proxiedCompanyId
	 */
	public int getProxiedCompanyId() {
		return (Integer) infoMap.get(JAASConstants.PROXIED_COMPANY_ID);
	}

	/**
	 * @param proxiedCompanyId the proxiedCompanyId to set
	 */
	public void setProxiedCompanyId(int proxiedCompanyId) {
		this.infoMap.put(JAASConstants.PROXIED_COMPANY_ID,proxiedCompanyId);
	}

	public String getInstanceId() {
		return (String) infoMap.get(JAASConstants.INSTANCE_ID);
	}

	public void setInstanceId(String instanceId) {
		this.infoMap.put(JAASConstants.INSTANCE_ID,instanceId);
	}

	public boolean isProxy() {
		if(infoMap.get(JAASConstants.IS_PROXY) == null)
		{
			return false;
		}
		return ((Boolean) infoMap.get(JAASConstants.IS_PROXY)).booleanValue();
	}

	public void setProxy(boolean isProxy) {
		infoMap.put(JAASConstants.IS_PROXY, isProxy);
	}

	public AuthenticationInfo() {
		infoMap.put(JAASConstants.COMPANY_ACRONYM, "");
		infoMap.put(JAASConstants.LOGIN_NAME, "");
		infoMap.put(JAASConstants.PASSWORD, "");
		infoMap.put(JAASConstants.IS_PROXY, false);
		infoMap.put(JAASConstants.INSTANCE_ID, "");
		//infoMap.put(JAASConstants.PARENT_COMPANY_ID, 0);
		infoMap.put(JAASConstants.PROXIED_COMPANY_ID, "");
	}

	public AuthenticationInfo(ClientType clientType, String userName,
			String password, String companyAcronym,boolean isProxy) {

		infoMap.put(JAASConstants.COMPANY_ACRONYM, companyAcronym);
		infoMap.put(JAASConstants.LOGIN_NAME, userName);
		infoMap.put(JAASConstants.PASSWORD, password);
		infoMap.put(JAASConstants.IS_PROXY, isProxy);
		infoMap.put(CLIENT_TYPE, clientType);
	}

	public AuthenticationInfo(ClientType clientType, String userName,
			String password, String companyAcronym) {
		infoMap.put(JAASConstants.COMPANY_ACRONYM, companyAcronym);
		infoMap.put(JAASConstants.LOGIN_NAME, userName);
		infoMap.put(JAASConstants.PASSWORD, password);
		infoMap.put(CLIENT_TYPE, clientType);
	}

	public AuthenticationInfo(ClientType clientType, String userName,
			String password) {
		this(clientType, userName, password, null);
	}

	public String getUserName() {
		return (String) infoMap.get(JAASConstants.LOGIN_NAME);
	}

	public void setUserName(String userName) {
		this.infoMap.put(JAASConstants.LOGIN_NAME, userName);
	}

	public String getPassword() {
		return (String) infoMap.get(JAASConstants.PASSWORD);
	}

	public void setPassword(String password) {
		this.infoMap.put(JAASConstants.PASSWORD, password);
	}

	public String getCompanyAcronym() {
		return (String) infoMap.get(JAASConstants.COMPANY_ACRONYM);
	}

	public void setCompanyAcronym(String companyAcronym) {
		this.infoMap.put(JAASConstants.COMPANY_ACRONYM, companyAcronym);
	}

	public ClientType getClientType() {
		return (ClientType) infoMap.get(CLIENT_TYPE);
	}

	public void setClientType(ClientType clientType) {
		this.infoMap.put(CLIENT_TYPE, clientType);
	}

	public String getPrintableString() {
		return "{ clientType = " + infoMap.get(CLIENT_TYPE) + ", userId = " + infoMap.get(JAASConstants.LOGIN_NAME) + " }";
	}

	/**
	 * {@Deprecated  } Use getParentId instead 
	 * @return the storeCompanyId
	 */
	@Deprecated
	public int getStoreCompanyId() {
		return (Integer) infoMap.get(JAASConstants.PARENT_COMPANY_ID);
	}

	/**
	 * @deprecated Use setParentId instead
	 * @param storeCompanyId the storeCompanyId to set
	 */
	@Deprecated
	public void setStoreCompanyId(int storeCompanyId) {
		this.infoMap.put(JAASConstants.PARENT_COMPANY_ID, storeCompanyId);
	}

	/**
	 * @return the Parent Company Id
	 */
	public int getParentId() {		if(this.infoMap.get(JAASConstants.PARENT_COMPANY_ID)==null)		{			return 0;		}				return ((Integer)this.infoMap.get(JAASConstants.PARENT_COMPANY_ID)).intValue();		
	}

	/**
	 * @param parentCompanyId the parentCompanyId to set
	 */
	public void setParentId(int parentId) {
		this.infoMap.put(JAASConstants.PARENT_COMPANY_ID, parentId);
	}

	/**
	 * @return the infoMap
	 */
	public Map<String, Object> getInfoMap() {
		return infoMap;
	}

	/**
	 * @param infoMap the infoMap to set
	 */
	public void setInfoMap(Map<String, Object> infoMap) {
		this.infoMap = infoMap;
	}
	
	public Object getAuthInfo(String key){
		return infoMap.get(key);
	}

	/**
	 * @param infoMap the infoMap to set
	 */
	public void setAuthInfo(String key, Object value) {
		this.infoMap.put(key, value);
	}
	
	public String toString() {
		return "AuthInfo" + getPrintableString();
	}

	public String getLoginCompanyUrl() {
		return (String) this.infoMap.get(JAASConstants.LOGIN_COMPANY_URL);
	}
	public void setLoginCompanyUrl(String url)
	{
		this.infoMap.put(JAASConstants.LOGIN_COMPANY_URL, url);
	}
	/*public int getLoginCompanyId() {
		if(this.infoMap.get(JAASConstants.LOGIN_COMPANY_ID) == null)
		{
			return 0;
		}
		return ((Integer) this.infoMap.get(JAASConstants.LOGIN_COMPANY_ID)).intValue();
	}
	public void setLoginCompanyId(int id)
	{
		this.infoMap.put(JAASConstants.LOGIN_COMPANY_ID, id);
	}*/

	public String getEOrgCompanyId() {
		return this.infoMap.get(JAASConstants.E_ORG_COMPANY_ID).toString();
	}
	public void setEOrgCompanyId(String id)
	{
		this.infoMap.put(JAASConstants.E_ORG_COMPANY_ID, id);
	}
}
