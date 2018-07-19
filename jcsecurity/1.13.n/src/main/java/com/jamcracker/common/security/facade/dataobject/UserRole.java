/*
 * Class: UserRole
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Initial version
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
package com.jamcracker.common.security.facade.dataobject;

import java.util.HashMap;
import java.util.Map;

/**
 * This class represents the User role. As we don't have separate data
 * model for JCBilling role, we have to extract the information from
 * JCPRoleDetails
 */
public final class UserRole implements java.io.Serializable {

	private static final long serialVersionUID = 9022521673249520750L;
	private static Map<Integer, UserRole> rolesMap = new HashMap<Integer, UserRole>();
	/**
	 * Possible of roles
	 */
	public static final UserRole MARKETPLACE_ADMIN = new UserRole(1,
			"marketplace-admin");
	public static final UserRole CUSTOMER_ADMIN = new UserRole(2,
			"customer-admin");
	public static final UserRole PARTNER_ADMIN = new UserRole(3,
			"partner-admin");

	public static final UserRole MARKETPLACE_USER = new UserRole(4,
			"marketplace-user");
	public static final UserRole CUSTOMER_USER = new UserRole(5,
			"customer-user");
	public static final UserRole PARTNER_USER = new UserRole(6, "partner-user");

	/**
	 * default/unknown role.
	 */
	public static final UserRole DEFAULT = new UserRole(7, "default");
	/**
	 * JC Syndicator role.
	 */
	public static final UserRole SYNDICATOR_ADMIN = new UserRole(8,
			"syndicator-admin");
	
	public static final UserRole INDIVIDUAL_CUSTOMER = new UserRole(11,
	"individual-customer");
	/**
	 * JCP roles.
	 */
	private static final String JCP_ROLE_ENDUSER = "ENDUSER";
	private static final String JCP_ROLE_PROVIDERADMIN = "PROVIDERADMIN";
	private static final String JCP_ROLE_ORGANIZATIONADMIN = "ORGANIZATIONADMIN";

	/**
	 * role string
	 */
	private String userRole = null;
	private int userRoleId;

	private UserRole(int userRoleId, String userRole) {
		this.userRole = userRole;
		this.userRoleId = userRoleId;
		rolesMap.put(userRoleId, this);
	}

	/**
	 * Extracts the JC role.
	 * 
	 * @param roleDetails
	 * @param organization
	 * @return
	 */
	public static UserRole extractRole(int roleId)// ,Organization organization)
	{

		UserRole role = rolesMap.get(roleId);
		if (role == null) {
			role = DEFAULT;
		}
		return role;

	}

	public boolean isAdmin() {
		return MARKETPLACE_ADMIN.equals(this);
	}

	public boolean isCustomerAdmin() {
		return CUSTOMER_ADMIN.equals(this);
	}

	public boolean isPartenerAdmin() {
		return PARTNER_ADMIN.equals(this);
	}

	public boolean isDefaultUser() {
		return DEFAULT.equals(this);
	}
	
	public boolean equals(Object other) {

		if (other instanceof UserRole) {
			return this.userRole.equals(((UserRole) other).userRole);
		}

		return false;
	}

	public String toString() {
		return this.userRole;
	}
}
