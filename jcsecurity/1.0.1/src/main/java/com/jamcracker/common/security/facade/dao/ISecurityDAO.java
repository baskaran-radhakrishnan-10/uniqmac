/*
 * Class: ISecurityDAO
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/exception///jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/dao/ISecurityDAO.java>>
 * 2.0  04/03/2010   Nisha				1.0		    Added for menu rendering
 * 3.0  31/03/2010   Rajesh/Shireesh	1.0         Added getACLRole form userId.
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
package com.jamcracker.common.security.facade.dao;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.jamcracker.common.security.authorization.JCPMenu;
import com.jamcracker.common.security.authorization.JCPPrivilege;
import com.jamcracker.common.security.authorization.JCPRole;
import com.jamcracker.common.security.authorization.JCPRoleDetails;
import com.jamcracker.common.security.authorization.jaas.policy.PrincipalPermissionConfig;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.facade.dataobject.EntityInfo;
import com.jamcracker.common.security.facade.dataobject.RBACUserRole;
import com.jamcracker.common.sql.facade.dao.IDAO;

public interface ISecurityDAO extends IDAO {
	/**
	 * This method is used to retrieve privileges to given role.
	 * 
	 * @param roleId
	 * @return
	 * @throws SecurityException
	 */
	public Set<JCPPrivilege> getRolePrivileges(int roleId)
			throws SecurityException;

	/**
	 * This method returns the JCPRole for given the role id.
	 * 
	 * @param roleId
	 * @return
	 * @throws SecurityException
	 */
	public JCPRole getRole(int roleId) throws SecurityException;
	
	/**
	 * This method returns the ACLRole for given the user id.
	 * 
	 * @param userId
	 * @return
	 * @throws SecurityException
	 */
	public RBACUserRole getAclRoleId(int userId) throws SecurityException;

	/**
	 * This method returns the Proxy ACLRole for given the company id.
	 * 
	 * @param companyId
	 * @return
	 * @throws SecurityException
	 */
	public RBACUserRole getProxyAclRoleId(int companyId) throws SecurityException;
	
	
	/**
	 * This method returns the Guest ACLRole for given the company id.
	 * 
	 * @param companyId
	 * @return
	 * @throws SecurityException
	 */
	public RBACUserRole getGuestAclRoleId(int companyId) throws SecurityException;
	
	/**
	 * This method returns the JCPRoleDetails for given role id and language
	 * code.
	 * @return
	 * @throws SecurityException
	 */
	public JCPRoleDetails getRoleDetails(int roleId, String languageCode)
			throws SecurityException;

	/**
	 * This method returns permissions in the system and associated
	 * privileges as "PrincipalPermissionConfig" list for given company Id.
	 * @param companyId
	 * @return
	 * @throws SecurityException
	 */
	public List<PrincipalPermissionConfig> getPermissions(int companyId) throws SecurityException; 
	/**
	 * This method return all the menus.
	 * @return
	 * @throws SecurityException
	 */
	public List<JCPMenu> getAllMenus()throws SecurityException;
	/**
	 * This method return instance role id
	 * @param userId
	 * @param instanceId
	 * @return Integer
	 * @throws SecurityException
	 */
	public Integer getInstanceRoleId(int userId, String instanceId) throws SecurityException;

	/**
	 * This method returns all permissions in the system and associated
	 * privileges as "PrincipalPermissionConfig" for cloud instances
	 * 
	 * @return
	 * @throws SecurityException
	 */
	public List<PrincipalPermissionConfig> getInstancePermissions() throws SecurityException;
	
    /**
	 * This method is used to get role's permission for an entity/entities
	 * @param int roleId
	 * @param int entityInfo
	 * @return boolean
     * @throws SecurityException
	 */
    public boolean getEntityPermission(int roleId, EntityInfo entityInfo) throws SecurityException; 
    
    /**
     * This method will return the  Login Module Name , either LDAP or SAML
     * @param companyId
     * @return
     * @throws SecurityException
     */
    public List<String> getAuthLoginModuleList(int companyId) throws SecurityException;
}
