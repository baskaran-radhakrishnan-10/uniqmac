/*
 * Class: DBPermissionAdapter
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authorization/jaas/policy/DBPermissionAdapter.java>>
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
package com.jamcracker.common.security.authorization.jaas.policy;

import static com.jamcracker.common.security.constants.JCSecurityConstants.JC_SECURITY_DAO;
import static com.jamcracker.common.security.constants.JCSecurityConstants.RBAC_POLICY_PERMISSION_REGION;

import java.lang.reflect.Constructor;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.jamcracker.common.jccache.CacheFactory;
import com.jamcracker.common.jccache.CacheService;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.facade.dao.ISecurityDAO;
import com.jamcracker.common.security.util.SpringConfigLoader;

/**
 * 
 * The DBPermissionAdapter is useful to fetch permissions from the database.
 */
public final class DBPermissionAdapter implements PermissionAdapter {

	private static final Logger LOGGER = Logger.getLogger(DBPermissionAdapter.class);

	private static DBPermissionAdapter instance = null;
	
	private static CacheService cacheService = CacheFactory.getCacheService();
	
	private static HashMap principalPermissionsMap = new HashMap();

	/**
	 * Private constructor to support Singleton.
	 */
	private DBPermissionAdapter() {

	}

	/**
	 * Static block to instantiate this class.
	 */
	static {
		instance = new DBPermissionAdapter();
	}

	/**
	 * Instance block to load instance permissions.
	 */
	{
		loadPrincipalPermissions();
	}

	public static DBPermissionAdapter getInstance() {

		if (instance == null) {
			instance = new DBPermissionAdapter();
		}

		return instance;
	}

	public PermissionCollection getPermissions(CodeSource codeSource) {

		/**
		 * No support for code source, will support only role based Return empty
		 * collection.
		 */
		return new PolicyPermissionCollection();
	}

	@SuppressWarnings("unchecked")
	public PermissionCollection getPermissions(ProtectionDomain domain) {

		LOGGER.debug("getPermissions() : START");

		Principal[] principals = domain.getPrincipals();
		int principalId;
		HashSet<Permission> permList;
		PolicyPermissionCollection policyPermission = new PolicyPermissionCollection();
		LOGGER.debug("principals Value before If condition " + principals);
			if (principals != null && principals.length > 0) {
			LOGGER.debug("principals Value after If condition " + principals.length);
			for (int i = 0; i < principals.length; i++) {
				LOGGER.info("PrivilegePrincipal is ============ "
						+ PrivilegePrincipal.class.getClassLoader()
						+ "  |  principals[i] is ============ "
						+ (Object) principals[i].getClass().getClassLoader());
				
				principalId = ((PrivilegePrincipal) principals[i]).getPrivilegeId();
				
				/* 
				 * InstanceId is not null then we will get permission list from instancePermissionMap 
				 * which contains permissions for cloud privileges. 
				 */
				permList = (HashSet<Permission>) principalPermissionsMap.get(principalId);
				
				policyPermission.addAll(permList);
			}
		}
		LOGGER.debug("getPermissions() : END");
		
		return policyPermission;
	}


	private void loadPrincipalPermissions() {
		try {
			LOGGER.debug(" start loadPrincipalPermissions() Method of DBPermissionAdapter ");
			ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JC_SECURITY_DAO);
			PrincipalPermissionConfig principalPerm;
			List<PrincipalPermissionConfig> principalPerms = securityDAO.getPermissions();
			int principalId = 0;
			Permission loadedPermission = null;
			HashSet<Permission> perms = null ;
			for (int i = 0; i < principalPerms.size(); i++) {
				principalPerm = principalPerms.get(i);
				loadedPermission = loadPermission(principalPerm);
				if(LOGGER.isDebugEnabled()){
					LOGGER.debug("Previous record principalId is ==== " + principalId);
					LOGGER.debug("Next Record principalId is ==== " + principalPerm.getPrincipalId());
				}
				if(principalId == principalPerm.getPrincipalId()){
					if(LOGGER.isDebugEnabled()){
						LOGGER.debug("Previous and next record principalId are matched. Adding to existing perms ==== ");
					}
					if (loadedPermission != null) {
					 	perms.add(loadedPermission);
					}
				}else{
					if(principalId != 0){
						LOGGER.info("Added principalId into clas level map is ==== " + principalId);
						principalPermissionsMap.put(principalId, perms);
						perms = null;			
					}
					if(LOGGER.isDebugEnabled()){
						LOGGER.debug("Previous and next record principalId are not matched. Adding to new perms ==== ");
					}
					principalId = principalPerm.getPrincipalId();
					if (perms == null) {
						perms = new HashSet<Permission>();
					}// create new list for this principal
					if (loadedPermission != null) {
						perms.add(loadedPermission);
					}
					  
				}
				
				/* If last permission (ie. privilegeID) is not already added in the map,  only HashSet<Permission> perms object gets populated with new permission.
				   But it is not being added in the principalPermissionsMap. Added bellow code to add the last privilege to the map.
				 */
				if(i==principalPerms.size()-1 && principalId != 0)
				{
				   LOGGER.debug("Added for last privilage adding in to the map" + principalId);
				    if( null == principalPermissionsMap.get(principalId))
				        principalPermissionsMap.put(principalId, perms);
				    
				   }
			}
			LOGGER.debug(" END loadPrincipalPermissions() Method of DBPermissionAdapter ");
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			LOGGER.error("Error in loadPrincipalPermissions() Method of DBPermissionAdapter", e);
		}
	}	

	private Permission loadPermission(PrincipalPermissionConfig principalPerm) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
			.debug(" start loadPermission() Method of DBPermissionAdapter ");
		}
		Permission loadedPermission = null;

		try {
			String permClass = principalPerm.getResourcePermissionClass();
			Class<?> clazz = Class.forName(permClass);
			Constructor<?> constructor = clazz.getConstructor(new Class[] {
					String.class, String.class , String.class });

			Object permissionObj = constructor.newInstance(principalPerm
					.getResourceName(), principalPerm.getResourceAction(),principalPerm.getDynamicPermissionClassName());

			loadedPermission = (Permission) permissionObj;
			LOGGER.debug("loadedPermission : " + loadedPermission);
		} catch (Exception e) {
			LOGGER.error("Error while loading permissions", e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER
			.debug(" END loadPermission() Method of DBPermissionAdapter ");
		}
		return loadedPermission;
	}

	/*
	 * Method used to delete the ActionPermission Map from HashTable. So that for the next time login we can reload the permissions from DB.
	 * Currently its loading for every restart. This we can call 
	 * 
	 * @author Surendra Babu
	 */
	@SuppressWarnings("unchecked")
	public void removeActorPermission(int companyId) {
		LOGGER.debug("Entered into method removeActorPermission in DBPermissionAdapter");

		Map<String, List<Permission>> principlePermissionMap = null;
		principlePermissionMap = (Map<String, List<Permission>>) cacheService.getValue(RBAC_POLICY_PERMISSION_REGION, companyId);

		if (principlePermissionMap != null && !principlePermissionMap.isEmpty()) {
			LOGGER.debug("actorPermissionMap object having the key " + companyId + ". So removing the key from hashtable");
			cacheService.removeValue(RBAC_POLICY_PERMISSION_REGION, companyId);
		}

		LOGGER.debug("End of method removeActorPermission in DBPermissionAdapter");
	}
}
