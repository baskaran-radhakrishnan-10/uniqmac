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

import java.lang.reflect.Constructor;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.jamcracker.common.jccache.CacheHandler;
import static com.jamcracker.common.security.constants.JCSecurityConstants.*;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.facade.dao.ISecurityDAO;
import com.jamcracker.common.security.util.SpringConfigLoader;

/**
 * 
 * The DBPermissionAdapter is useful to fetch permissions from the database.
 */
public class DBPermissionAdapter implements PermissionAdapter {

	private static Logger LOGGER = Logger.getLogger(DBPermissionAdapter.class);

	private static DBPermissionAdapter instance = null;

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
		loadPrincipalInstancePermissions();
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
		int companyId;
		String principalName;
		String instanceId;
		List<Permission> permList;
		Map<String, List<Permission>> principlePermissionMap;
		PolicyPermissionCollection policyPermission = new PolicyPermissionCollection();
		
		if (principals != null && principals.length > 0) {

			// Fetch the RBAC Organization Id.
			companyId = ((PrivilegePrincipal) principals[0]).getCompanyId();

			// Fetch the Organization Permission Map.
			principlePermissionMap = (Map<String, List<Permission>>) CacheHandler.getValue(RBAC_POLICY_PERMISSION_REGION, companyId);
			
			if (principlePermissionMap == null || principlePermissionMap.isEmpty()) {
				principlePermissionMap = loadPrincipalPermissions(companyId);
				CacheHandler.putValue(RBAC_POLICY_PERMISSION_REGION, companyId, principlePermissionMap);
			}

			for (int i = 0; i < principals.length; i++) {

				principalName = principals[i].getName();

				instanceId = ((PrivilegePrincipal) principals[i]).getInstanceId();

				/* 
				 * InstanceId is not null then we will get permission list from instancePermissionMap 
				 * which contains permissions for cloud privileges. 
				 */
				if (instanceId == null || EMPTY.equals(instanceId)) {
					permList = (List<Permission>) principlePermissionMap.get(principalName);
				} else {
					permList = (List<Permission>) CacheHandler.getValue(RBAC_INSTANCE_PERMISSION_REGION, principalName);
				}

				policyPermission.addAll(permList);

			}

		}

		LOGGER.debug("getPermissions() : END");

		return policyPermission;
	}


	private Map<String, List<Permission>> loadPrincipalPermissions(int companyId) {
		Map<String, List<Permission>> latestPrinciplePermissionMap = new Hashtable<String, List<Permission>>();
		try {
			LOGGER.debug(" start loadPrincipalPermissions() Method of DBPermissionAdapter ");
			LOGGER.debug(" start loadPrincipalPermissions():: companyId = "+companyId);


			ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JC_SECURITY_DAO);
			PrincipalPermissionConfig principalPerm;
			List<PrincipalPermissionConfig> principalPerms = securityDAO.getPermissions(companyId);

			String principalName = null;
			List<Permission> perms = null;
			Permission loadedPermission = null;

			for (int i = 0; i < principalPerms.size(); i++) {

				principalPerm = principalPerms.get(i);
				principalName = principalPerm.getPrincipalName();
				perms = latestPrinciplePermissionMap.get(principalName);

				if (perms == null) {
					perms = new ArrayList<Permission>();
				}// create new list for this principal
				loadedPermission = loadPermission(principalPerm);
				if (loadedPermission != null) {
					perms.add(loadedPermission);
				}// add loaded permission
				// update principle-permission collection map.
				latestPrinciplePermissionMap.put(principalName, perms);

			}
			LOGGER.debug(" END loadPrincipalPermissions() Method of DBPermissionAdapter ");
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			LOGGER.error("Error in loadPrincipalPermissions() Method of DBPermissionAdapter", e);
		}
		return latestPrinciplePermissionMap;
	}
	/* This method used to load the permissions for cloud privileges. 
	 */
	@SuppressWarnings("unchecked")
	private void loadPrincipalInstancePermissions() {

		try {

			LOGGER.info("loadPrincipalInstancePermissions() : START");

			ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JC_SECURITY_DAO);
			PrincipalPermissionConfig principalPerm;
			List<PrincipalPermissionConfig> principalPerms = securityDAO.getInstancePermissions();

			String principalName = null;
			List<Permission> perms = null;
			Permission loadedPermission = null;

			// Populate the instance privilege permissions to cache.
			for (int i = 0; i < principalPerms.size(); i++) {

				principalPerm = principalPerms.get(i);
				principalName = principalPerm.getPrincipalName();
				perms = (List<Permission>) CacheHandler.getValue(RBAC_INSTANCE_PERMISSION_REGION, principalName);

				if (perms == null) {
					perms = new ArrayList<Permission>();
				}

				// Load the instance permission.
				loadedPermission = loadPermission(principalPerm);

				if (loadedPermission != null) {
					perms.add(loadedPermission);
				}

				// Update the cache with instance specific privilege permission.
				CacheHandler.putValue(RBAC_INSTANCE_PERMISSION_REGION, principalName, perms);
			}

			LOGGER.info("loadPrincipalInstancePermissions() : END");
		} catch (SecurityException e) {
			LOGGER.error("Error in loadPrincipalInstancePermissions()", e);
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
		principlePermissionMap = (Map<String, List<Permission>>) CacheHandler.getValue(RBAC_POLICY_PERMISSION_REGION, companyId);

		if (principlePermissionMap != null && !principlePermissionMap.isEmpty()) {
			LOGGER.debug("actorPermissionMap object having the key " + companyId + ". So removing the key from hashtable");
			CacheHandler.removeValue(RBAC_POLICY_PERMISSION_REGION, companyId);
		}

		LOGGER.debug("End of method removeActorPermission in DBPermissionAdapter");
	}
}
