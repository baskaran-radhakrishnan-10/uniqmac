/**
 * 
 */
package com.jamcracker.common.security.authorization.jaas.permissions;

import java.util.Map;

import com.jamcracker.common.security.exception.SecurityException;
/**
 * @author rrangeneni
 *
 */
public interface IDynamicPermission {
	/**
	 * This method needs to implemented for additional dynamic validation for resource.
	 *
	 * 
	 * @param abstractPermission
	 * @param userContextMap will have the following key-- value pairs 
	  		  IUserWebSession.USER -- com.jamcracker.directory.dataobject.UserInfo 
			  IUserWebSession.PIVOT_PATH_IDENTITY -- com.jamcracker.security.identity.Identity
			  IUserWebSession.USER_SECURITY_SHORT_INFO -- com.jamcracker.directory.dataobject.UserShortInfo
			  IUserWebSession.USER_ROLE -- com.jamcracker.common.security.authorization.JCPRole
			  IUserWebSession.USER_ROLE_DETAILS -- com.jamcracker.common.security.authorization.JCPRoleDetails
			  IUserWebSession.USER_JC_ROLE -- com.jamcracker.common.security.facade.dataobject.UserRole
			  IUserWebSession.USER_ORGANIZATION -- com.jamcracker.directory.dataobject.CompanyShortInfo
	 * @return boolean
	 * @throws SecurityException
	 */
	public abstract boolean implies( AbstractPermission abstractPermission,	Map<String, Object> userContextMap) throws SecurityException;

}
