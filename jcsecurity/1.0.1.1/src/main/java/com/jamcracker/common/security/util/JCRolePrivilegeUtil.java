/*
 * Class: JCRolePrivilegeUtil
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/common/util/TSMRolePrivilegeUtil.java>>
 * 2.0  04/03/2010   Nisha			    1.0	        Added for menu rendering
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
package com.jamcracker.common.security.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.jamcracker.common.security.authorization.JCPPrivilege;
import com.jamcracker.common.security.facade.dataobject.UserRole;

/**
 * This utility is useful to extract role privileges.
 */
public abstract class JCRolePrivilegeUtil {

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(JCRolePrivilegeUtil.class.getName());

	/**
	 * The privilege start range. We may need to load this from some properties
	 * file.
	 */
	private static final int PRIVILEGE_START_RANGE = 6;
	private static final String PRIVILEGE_COMMON = "common";
	private static final String PRIVILEGE_SEPARATOR = "-";

	/**
	 * Syndicator admin pivot path role ID.
	 */
	private static final int SYNDICATOR_ADMIN_PIVOTPATH_ROLE_ID = 10;
	
	private static final int INDIVIDUAL_CUSTOMER_PIVOTPATH_ROLE_ID = 11;

	public static boolean isSyndicatorAdmin(int pivotPathRoleId) {
		return (pivotPathRoleId == SYNDICATOR_ADMIN_PIVOTPATH_ROLE_ID);
	}
	
	public static boolean isIndividualCustomer(int pivotPathRoleId) {
		return (pivotPathRoleId == INDIVIDUAL_CUSTOMER_PIVOTPATH_ROLE_ID);
	}

	public static int getPrivilegeStartRange() {
		return PRIVILEGE_START_RANGE;
	}

	private static String getRolePrivilegePrefix(UserRole jcRole) {
		return (jcRole + PRIVILEGE_SEPARATOR);
	}

	private static String getCommonPrivilegePrefix() {
		return (PRIVILEGE_COMMON + PRIVILEGE_SEPARATOR);
	}

	/**
	 * Since the roles from pivot path are mapped to multiple roles we need to
	 * filter out the privileges based on role
	 * 
	 * @see
	 * @return Set<JCPPrivilege>
	 */
	public static List<JCPPrivilege> getRolePrivileges(UserRole jcRole,
			Set<JCPPrivilege> privileges) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start getRolePrivileges() method of JCRolePrivilegeUtil ");
		}
		/**
		 * This role is not a role/default So nothing to filter, just ignore.
		 */
		List<JCPPrivilege> jcpPrivileges = new ArrayList<JCPPrivilege>();
		if (jcRole.isDefaultUser()) {
			jcpPrivileges.addAll(privileges);
			return jcpPrivileges;
		}

		String commonPrvilegePrefix = getCommonPrivilegePrefix();
		String rolePrvilegePrefix = getRolePrivilegePrefix(jcRole);

		Iterator<JCPPrivilege> privilegesIt = privileges.iterator();
		JCPPrivilege jcpPrivilege = null;
		while (privilegesIt.hasNext()) {

			jcpPrivilege = privilegesIt.next();

			if (jcpPrivilege.getName() != null
					&& (jcpPrivilege.getName().startsWith(commonPrvilegePrefix) || jcpPrivilege
							.getName().startsWith(rolePrvilegePrefix))) {
				jcpPrivileges.add(jcpPrivilege);
        	}
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" END getRolePrivileges() method of JCRolePrivilegeUtil ");
		}
		return jcpPrivileges;
	}
}
