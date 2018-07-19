/*
 * Class: GenericSecurityDAO
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Initial version
 * 2.0  04/03/2010   Nisha      		1.0			Added for menu rendering
 * 3.0	31/03/2010	 Rajesh/Shireesh	1.0			Added getRole form actorID method for ACLService.
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

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import com.jamcracker.common.security.authorization.JCPMenu;
import com.jamcracker.common.security.authorization.JCPPrivilege;
import com.jamcracker.common.security.authorization.JCPRole;
import com.jamcracker.common.security.authorization.JCPRoleDetails;
import com.jamcracker.common.security.authorization.jaas.policy.PrincipalPermissionConfig;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.exception.SecurityFaultCode;
import com.jamcracker.common.security.facade.dataobject.Entity;
import com.jamcracker.common.security.facade.dataobject.EntityInfo;
import com.jamcracker.common.security.facade.dataobject.RBACUserRole;
import com.jamcracker.common.security.facade.rowmapper.ACLRoleIdRowMapper;
import com.jamcracker.common.security.facade.rowmapper.LoginModuleRowMapper;
import com.jamcracker.common.security.facade.rowmapper.MenuRowMapper;
import com.jamcracker.common.security.facade.rowmapper.PermissionsRowMapper;
import com.jamcracker.common.security.facade.rowmapper.PrivilegesRowMapper;
import com.jamcracker.common.security.facade.rowmapper.RBACRoleRowMapper;
import com.jamcracker.common.security.facade.rowmapper.RoleDetailsRowMapper;
import com.jamcracker.common.security.facade.rowmapper.RoleRowMapper;
import com.jamcracker.common.sql.dataobject.JCPersistenceInfo;
import com.jamcracker.common.sql.spring.facade.dao.BaseSpringDAO;
import com.jamcracker.common.security.facade.rowmapper.EntityPermissionRowMapper;
import com.jamcracker.common.util.GlobalizationUtil;
/**
 * Implementation class for Security DAO. This facilitates basic user CRUD
 * operation.
 */

public class GenericSecurityDAO extends BaseSpringDAO implements ISecurityDAO {
	

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(GenericSecurityDAO.class.getName());
	
	/**
	 * This method returns the JCPRoleDetails for given role id and language
	 * code.
	 * 
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	public JCPRoleDetails getRoleDetails(int roleId, String languageCode)
			throws SecurityException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start getRoleDetails() Method of GenericSecurityDAO ");
		}
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		JCPRoleDetails jcproleDetails;
		List roleDetailsList = null;
		jcPersistenceInfo = new JCPersistenceInfo();
		try {
			Object[] objectUpdateValue = new Object[] { roleId, languageCode };
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getRole_details");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new RoleDetailsRowMapper());
			roleDetailsList = query(jcPersistenceInfo);
			Iterator roleDetIterator = roleDetailsList.iterator();

			if (roleDetIterator.hasNext()) {
				jcproleDetails = (JCPRoleDetails) roleDetIterator.next();
			} else {
				jcproleDetails = new JCPRoleDetails();
				jcproleDetails.setRoleId(roleId);
				jcproleDetails.setLanguageCode(languageCode);
			}
		} catch (Exception e) {
			LOGGER.error("Getting role DETAILS failed: ", e);
			throw new SecurityException(
					SecurityFaultCode.FAILED_TO_GET_ROLE_DETAILS, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end getRoleDetails() Method of GenericSecurityDAO ");
		}
		return jcproleDetails;
	}

	/**
	 * This method is used to retrieve privileges to given role.
	 * 
	 * @param roleId
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	public Set<JCPPrivilege> getRolePrivileges(int roleId)
			throws SecurityException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start getRolePrivileges() Method of GenericSecurityDAO ");
		}
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		jcPersistenceInfo = new JCPersistenceInfo();
		List privilegeList = null;
		Set rolePrivilegeSet = null;
		try {
			Object[] objectUpdateValue = new Object[] { roleId, GlobalizationUtil.getLanguageCode() };
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getRole_privileges");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new PrivilegesRowMapper());
			privilegeList = query(jcPersistenceInfo);
			rolePrivilegeSet = new HashSet(privilegeList);
		} catch (Exception e) {
			LOGGER.error("Getting role privilages failed: ", e);
			throw new SecurityException(
					SecurityFaultCode.FAILED_TO_GET_ROLE_PRIVILEGES, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" end getRolePrivileges() Method of GenericSecurityDAO ");
		}
		return rolePrivilegeSet;
	}

	/**
	 * This method returns permissions in the system and associated
	 * privileges as "PrincipalPermissionConfig" list for given company Id.
	 * 
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<PrincipalPermissionConfig> getPermissions(int companyId) throws SecurityException {
		LOGGER.debug(" start getPermissions() Method of GenericSecurityDAO ");
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		List permissionList = null;
		jcPersistenceInfo = new JCPersistenceInfo();
		try {
			Object[] objectUpdateValue = new Object[] { companyId, GlobalizationUtil.getLanguageCode() };
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("get_Permissions");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new PermissionsRowMapper());
			permissionList = query(jcPersistenceInfo);

		} catch (Exception e) {
			LOGGER.error("Getting getPermissions failed: ", e);
			throw new SecurityException(
					SecurityFaultCode.FAILED_TO_GET_PERMISSIONS, e);
		}
		LOGGER.debug(" end getPermissions() Method of GenericSecurityDAO ");
		return permissionList;
	}
	/**
	 * This method returns all permissions in the system and associated
	 * privileges as "PrincipalPermissionConfig" for cloud instances
	 * 
	 * @return
	 * @throws SecurityException
	 */
	public List<PrincipalPermissionConfig> getInstancePermissions() throws SecurityException {
		LOGGER.debug(" start getInstancePermissions() Method of GenericSecurityDAO ");
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		List permissionList = null;
		jcPersistenceInfo = new JCPersistenceInfo();
		try {
			Object[] objectUpdateValue = new Object[] {GlobalizationUtil.getLanguageCode() };
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("get_instance_Permissions");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new PermissionsRowMapper());
			permissionList = query(jcPersistenceInfo);

		} catch (Exception e) {
			LOGGER.error("Getting getInstancePermissions failed: ", e);
			throw new SecurityException(
					SecurityFaultCode.FAILED_TO_GET_INSTANCE_PERMISSIONS, e);
		}
		LOGGER.debug(" end getInstancePermissions() Method of GenericSecurityDAO ");
		return permissionList;
	}
	/**
	 * This method returns the JCPRole for given the role id.
	 * 
	 * @param roleId
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	@Override
	public JCPRole getRole(int roleId) throws SecurityException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start getRole() Method of GenericSecurityDAO ");
		}
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		jcPersistenceInfo = new JCPersistenceInfo();
		JCPRole JCProle = null;
		List roleList = null;
		try {
			Object[] objectUpdateValue = new Object[] { roleId };
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getRole");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new RoleRowMapper());
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(" moduleName is "
						+ jcPersistenceInfo.getModuleName()
						+ " SqlQueryName is "
						+ jcPersistenceInfo.getSqlQueryName()
						+ " sqlParams is " + jcPersistenceInfo.getSqlParams()
						+ " rowMapper is in GenericSecurityDAO >>> "
						+ jcPersistenceInfo.getRowMapper());
			}
			roleList = query(jcPersistenceInfo);
			Iterator roleIterator = roleList.iterator();

			if (roleIterator.hasNext()) {
				JCProle = (JCPRole) roleIterator.next();
			} else {
				JCProle = new JCPRole();
				JCProle.setRoleId(roleId);
			}
			JCProle.setPrivileges(getRolePrivileges(roleId));
		} catch (Exception e) {
			LOGGER.error("Getting role failed: ", e);
			throw new SecurityException(SecurityFaultCode.FAILED_TO_GET_ROLE, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end getRole() Method of GenericSecurityDAO ");
		}

		return JCProle;
	}

	/**
	 * This method is to valid the token.
	 */
	/*@Override
	public boolean isValidToken(JCAuthenticationToken jcAuthToken)
			throws Exception {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start isValidToken() Method of GenericSecurityDAO ");
		}
		boolean flag = false;
		// TODO Auto-generated method stub
		AuthenticationAPI authAPI = JCAPIFactory.getAuthenticationAPI();
		flag = authAPI.isValidToken(jcAuthToken);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end isValidToken() Method of GenericSecurityDAO ");
		}
		return flag;
	}*/

	/**
	 * This method return all the menus from DB.
	 * @param roleId
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	public List<JCPMenu> getAllMenus()throws SecurityException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start getAllMenus() Method of GenericSecurityDAO ");
		}
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		List<JCPMenu> menuList = null;
		try {
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("get_all_menus");
			jcPersistenceInfo.setRowMapper(new MenuRowMapper());
			menuList = query(jcPersistenceInfo);
		} catch (Exception e) {
			LOGGER.error("Getting menus failed: ", e);
			throw new SecurityException(
					SecurityFaultCode.FAILED_TO_GET_MENUS, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end getAllMenus() Method of GenericSecurityDAO ");
		}
		return menuList;
	}
	
	/**
	 * This method returns the ACLRole for given the user id.
	 * 
	 * @param userId
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	@Override
	public RBACUserRole getAclRoleId(int userId) throws SecurityException {
		LOGGER.debug(" start getRoleId() Method of GenericSecurityDAO ");
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		jcPersistenceInfo = new JCPersistenceInfo();
		RBACUserRole rBACUserRole = null;
		List<RBACUserRole> roleList = null;
		int aclRoleId = 0;
		try {
			Object[] objectUpdateValue = new Object[] { userId, JCSecurityConstants.ACL_SERVICE_ID, JCSecurityConstants.ACL_STATUS, GlobalizationUtil.getLanguageCode()};
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getRoleId");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new RBACRoleRowMapper());
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(" moduleName is "
						+ jcPersistenceInfo.getModuleName()
						+ " SqlQueryName is "
						+ jcPersistenceInfo.getSqlQueryName()
						+ " sqlParams is " + jcPersistenceInfo.getSqlParams()
						+ " rowMapper is in GenericSecurityDAO >>> "
						+ jcPersistenceInfo.getRowMapper());
			}
			roleList = query(jcPersistenceInfo);
			Iterator roleIterator = roleList.iterator();

			if (roleIterator.hasNext()) {
				rBACUserRole =(RBACUserRole) roleIterator.next();
			} 
		} catch (Exception e) {
			LOGGER.error("Getting roleId failed: ", e);
			throw new SecurityException(SecurityFaultCode.FAILED_TO_GET_ROLE, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end getRole() Method of GenericSecurityDAO ");
		}

		return rBACUserRole;
	}
	
	/**
	 * This method return instance role id
	 * @param userId
	 * @param instanceId
	 * @return
	 * @throws SecurityException
	 */
	public Integer getInstanceRoleId(int userId, String instanceId) throws SecurityException{
		
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		jcPersistenceInfo = new JCPersistenceInfo();
		JCPRole jcprole = null;
		List roleList = null;
		Integer instanceRoleId=-1;
		try {
			Object[] objectUpdateValue = new Object[] { userId, instanceId};
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getInstanceRoles");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new ACLRoleIdRowMapper());
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(" moduleName is "
						+ jcPersistenceInfo.getModuleName()
						+ " SqlQueryName is "
						+ jcPersistenceInfo.getSqlQueryName()
						+ " sqlParams is " + jcPersistenceInfo.getSqlParams()
						+ " rowMapper is in GenericSecurityDAO >>> "
						+ jcPersistenceInfo.getRowMapper());
			}
			roleList = query(jcPersistenceInfo);
			Iterator roleIterator = roleList.iterator();

			if(roleIterator.hasNext()) {
				jcprole = (JCPRole)roleIterator.next();
				instanceRoleId = jcprole.getACLRoleId();
			} 
		} catch (Exception e) {
			LOGGER.error("Getting Instance roleIds failed: ", e);
			throw new SecurityException(SecurityFaultCode.FAILED_TO_GET_ROLE, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end getInstanceRoleIds() Method of GenericSecurityDAO ");
		}

		return instanceRoleId;
	}


	/**
	 * This method returns the Proxy ACLRole for given the company id.
	 * 
	 * @param companyId
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	@Override
	public RBACUserRole getProxyAclRoleId(int companyId) throws SecurityException {
		LOGGER.debug(" start getProxyAclRoleId() Method of GenericSecurityDAO ");
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		jcPersistenceInfo = new JCPersistenceInfo();
		RBACUserRole rBACUserRole = null;
		List roleList = null;
		int aclRoleId = 0;
		try {
			Object[] objectUpdateValue = new Object[] { companyId, GlobalizationUtil.getLanguageCode()};
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getProxyRoleId");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new RBACRoleRowMapper());
			LOGGER.debug(" moduleName is "
						+ jcPersistenceInfo.getModuleName()
						+ " SqlQueryName is "
						+ jcPersistenceInfo.getSqlQueryName()
						+ " sqlParams is " + jcPersistenceInfo.getSqlParams()
						+ " rowMapper is in GenericSecurityDAO >>> "
						+ jcPersistenceInfo.getRowMapper());
			roleList = query(jcPersistenceInfo);
			Iterator roleIterator = roleList.iterator();

			if (roleIterator.hasNext()) {
				rBACUserRole = (RBACUserRole)roleIterator.next();
			} 
		} catch (Exception e) {
			LOGGER.error("Getting proxy roleId failed: ", e);
			throw new SecurityException(SecurityFaultCode.FAILED_TO_GET_PROXY_ROLE, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end getProxyAclRoleId() Method of GenericSecurityDAO ");
		}

		return rBACUserRole;
	}
	
	/**
	 * This method returns the Guest ACLRole for given the company id.
	 * 
	 * @param companyId
	 * @return
	 * @throws SecurityException
	 */
	@SuppressWarnings("unchecked")
	@Override
	public RBACUserRole getGuestAclRoleId(int companyId) throws SecurityException {
		LOGGER.debug(" start getGuestAclRoleId() Method of GenericSecurityDAO ");
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		jcPersistenceInfo = new JCPersistenceInfo();
		RBACUserRole rBACUserRole = null;
		List roleList = null;
		int aclRoleId = 0;
		try {
			Object[] objectUpdateValue = new Object[] { companyId, GlobalizationUtil.getLanguageCode()};
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getGuestRoleId");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new RBACRoleRowMapper());
			LOGGER.debug(" moduleName is "
						+ jcPersistenceInfo.getModuleName()
						+ " SqlQueryName is "
						+ jcPersistenceInfo.getSqlQueryName()
						+ " sqlParams is " + jcPersistenceInfo.getSqlParams()
						+ " rowMapper is in GenericSecurityDAO >>> "
						+ jcPersistenceInfo.getRowMapper());
			roleList = query(jcPersistenceInfo);
			Iterator roleIterator = roleList.iterator();

			if (roleIterator.hasNext()) {
				rBACUserRole = (RBACUserRole)roleIterator.next();
			} 
		} catch (Exception e) {
			LOGGER.error("Getting guest roleId failed: ", e);
			throw new SecurityException(SecurityFaultCode.FAILED_TO_GET_GUEST_ROLE, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end getGuestAclRoleId() Method of GenericSecurityDAO ");
		}

		return rBACUserRole;
	}


	/**
	 * This method returns the role permission for an entity/entities.
	 * 
	 * @param companyId
	 * @return boolean
	 * @throws SecurityException
	 */
	@Override
	public boolean getEntityPermission(int roleId, EntityInfo entityInfo)
			throws SecurityException {
		
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start getEntityPermission() Method of GenericSecurityDAO ");
		}
		
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		boolean hasPermission = false;
		List<Entity> entityList = entityInfo.getEntityList();
		StringBuffer entities = new StringBuffer();
		for(int i=0;i<entityList.size();i++){
			Entity entity = (Entity)entityList.get(i);
			if(!(i==(entityList.size()-1))){
				entities.append(entity.getEntityId()+",");
			}else{
				entities.append(entity.getEntityId());
			}
			
		}
			LOGGER.debug(" parameters for getting entity permission : "+roleId+" "+entities.toString());
		try {
			Object[] objectUpdateValue = new Object[] {roleId,entities.toString()};
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getEntityPermission");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new EntityPermissionRowMapper());
			entityList = query(jcPersistenceInfo);
			Iterator<Entity> entityListIterator = entityList.iterator();

			if (entityListIterator.hasNext()) {
				hasPermission = true;
			}
		} catch (Exception e) {
			LOGGER.error("Getting role privilages failed: ", e);
			throw new SecurityException(
					SecurityFaultCode.FAILED_TO_GET_PERMISSIONS, e);
		}
			LOGGER
					.debug(" end getEntityPermission() Method of GenericSecurityDAO ");

		return hasPermission;
	}
    /**
     *  This method will return the  Login Module Name , either LDAP or SAML
     */
	@Override
	public List<String> getAuthLoginModuleList(int companyId)
			throws SecurityException {
		
		LOGGER.info(" start getAuthLoginModuleList() Method of GenericSecurityDAO ");
		
		JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
		jcPersistenceInfo = new JCPersistenceInfo();
		
		List<String> loginModulesList= null;
		
		try {
			LOGGER.debug(" getAuthLoginModuleList--> CompanyID : " + companyId);
			Object[] objectUpdateValue = new Object[] { companyId};
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("getLoginModuleType");
			jcPersistenceInfo.setSqlParams(objectUpdateValue);
			jcPersistenceInfo.setRowMapper(new LoginModuleRowMapper());
			loginModulesList =query(jcPersistenceInfo);
			LOGGER.debug(" LoginModuleList Size : " +  loginModulesList.size());
			
		} catch (Exception e) {
			LOGGER.error("Failed to fetch the LoginModule names : ", e);
			throw new SecurityException(SecurityFaultCode.FAILED_GET_LOGIN_MODULE, e);
		}
		LOGGER.debug(" end getAuthLoginModuleList() Method of GenericSecurityDAO ");

		return loginModulesList;
	}

}
