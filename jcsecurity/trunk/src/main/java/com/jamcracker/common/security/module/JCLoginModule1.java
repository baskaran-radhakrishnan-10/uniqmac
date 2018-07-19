/*
 * Class: JCLoginModule
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/jaas/loginmodule/JAASBaseLoginModule.java>>
 * 2.0  04/03/2010   Nisha			    1.0	        Added for menu rendering
 * 3.0  15/04/2010   Shireesh			1.0			Added for ClientType "UI"
 * 4.0  31/03/2010	 Rajesh/Shireesh	1.0  		Added for ACLService Service.
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
package com.jamcracker.common.security.module;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import com.jamcracker.api.AuthenticationAPI;
import com.jamcracker.api.JCAPIFactory;
import com.jamcracker.api.UserAPI;
import com.jamcracker.api.common.APIConstants;
import com.jamcracker.api.common.exception.JCApiException;
import com.jamcracker.api.search.UserSearchInfo;
import com.jamcracker.api.security.AuthenticationInfo;
import com.jamcracker.common.exception.CommonFaultCodes;
import com.jamcracker.common.exception.JCDynamicFaultCode;
import com.jamcracker.common.security.ClientType;
import com.jamcracker.common.security.authentication.jaas.JAASConstants;
import com.jamcracker.common.security.authorization.JCPPrivilege;
import com.jamcracker.common.security.authorization.JCPRole;
import com.jamcracker.common.security.authorization.JCPRoleDetails;
import com.jamcracker.common.security.authorization.jaas.policy.PrivilegePrincipal;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.exception.SecurityFaultCode;
import com.jamcracker.common.security.facade.dao.ISecurityDAO;
import com.jamcracker.common.security.facade.dataobject.RBACUserRole;
import com.jamcracker.common.security.facade.dataobject.UserRole;
import com.jamcracker.common.security.spec.ISecureSession;
import com.jamcracker.common.security.util.JCRolePrivilegeUtil;
import com.jamcracker.common.security.util.SpringConfigLoader;
import com.jamcracker.directory.company.facade.CompanyFacade;
import com.jamcracker.directory.dataobject.CompanyShortInfo;
import com.jamcracker.directory.dataobject.UserInfo;
import com.jamcracker.directory.dataobject.UserShortInfo;
import com.jamcracker.directory.user.facade.UserFacade;
import com.jamcracker.jcri.FacadeFactory;
import com.jamcracker.security.authentication.AuthenticationToken;
import com.jamcracker.security.common.exception.SecurityFaultCodes;
import com.jamcracker.security.identity.Identity;

/**
 * The JAAS login module implementation. This module validates the subject and
 * adds the appropriate principles.
 */

@Deprecated
public class JCLoginModule1 extends BaseLoginModule {

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(JCLoginModule1.class.getName());

	private static final String DEFAULT_LANGUAGE_CODE = "en_US";
	private ClientType clientType = ClientType.UNKNOWN;

	private UserInfo user = null;
	private UserRole userRole = null;
	private RBACUserRole rBACUserRole = null;
	private CompanyShortInfo organization = null;
	private JCPRole jcpRole = null;
	private JCPRoleDetails roleDetails = null;
	private Identity identity = null;
	private UserShortInfo usrShortInfo = null;
	
	/**
	 * true if this method succeeded, or false if this LoginModule should be
	 * ignored
	 */
	@Override
	public boolean commit() throws LoginException {
		LOGGER.debug(" start commit() Method of JCLoginModule ");
		
		ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_DAO);
		try {
			user = new UserInfo();
			UserFacade userFacade = FacadeFactory.getInstance().getUserFacade();
			/* Invoking userFacade to get usrShortInfo if login is for cloud instance 
			 * since we will not call isValidUser to authenticate user again if instance login
			 * usrShortInfo is populated in isValidUser method for JSDN Login
			 */
			if(!"".equals(instanceId))
				usrShortInfo= userFacade.getUserShortInfo(companyAcronym,userId);
			
			int luserId = usrShortInfo.getUserID();
			int pivotPathroleId = usrShortInfo.getUserRoleID();
			LOGGER.debug("User id found value is : " + userId);
			LOGGER.debug("User PivotPath role found value is : "+ pivotPathroleId);
		
			user.setUserID(luserId);
			user = userFacade.getUserInfo(luserId);
			int orgId = -1;
			//rbacOrgId will have user company id which is used to pass as constructor argument for PrivilegePrincipal
			int rbacOrgId = -1;
			if(JAASConstants.YES.equals(isProxy)){
				orgId = eorgCompanyId;
				rbacOrgId = eorgCompanyId;
			}
			else{
				 orgId = user.getCompanyID();
				 rbacOrgId = user.getCompanyID();
			
			}
			CompanyFacade companyFacade = FacadeFactory.getInstance()
					.getCompanyFacade();
			organization = companyFacade.getCompanyShortInfo(orgId);
			jcpRole = securityDAO.getRole(pivotPathroleId);
			roleDetails = securityDAO.getRoleDetails(pivotPathroleId,
					DEFAULT_LANGUAGE_CODE);
			userRole = UserRole.extractRole(pivotPathroleId);
			JCPPrivilege jcpPrivilege = null;
			List<JCPPrivilege> jcpRolePrivileges = new ArrayList<JCPPrivilege>();
			/* instanceId is not null then populate permission list in subject for cloud instances  
			 */
			if(instanceId == null || "".equals(instanceId)){
				//Loading jsdn privileges.....
				if(JAASConstants.YES.equals(isProxy)){
					orgId = eorgCompanyId;
					rbacOrgId = eorgCompanyId;
					rBACUserRole = securityDAO.getProxyAclRoleId(orgId);
		    	}else if(JAASConstants.GUEST_USER_ID == luserId){
					rBACUserRole = securityDAO.getGuestAclRoleId(storeCompanyId);
					/* Set rbacOrgId as store company id If guest user is logged in 
					since the privileges are defined at store level for guest user */
					rbacOrgId = storeCompanyId;
				}else
					rBACUserRole = securityDAO.getAclRoleId(luserId);

				if(rBACUserRole!=null){
					LOGGER.debug(" ACL Role is available");
					jcpRolePrivileges.addAll(securityDAO.getRolePrivileges(rBACUserRole.getRoleId()));
				}
				else
					rBACUserRole = new RBACUserRole();
				jcpRolePrivileges.addAll(jcpRole.getPrivileges());
				LOGGER.debug(" jcpRolePrivileges for jsdn in JCLoginmodule... "+jcpRolePrivileges);
				Iterator<JCPPrivilege> privilegesIt = jcpRolePrivileges.iterator();
				while (privilegesIt.hasNext()) {
					jcpPrivilege = privilegesIt.next();
					/**
					 * Get and add the privilege.
					 */
					subject.getPrincipals().add(
							new PrivilegePrincipal(jcpPrivilege.getPrivilegeId(), jcpPrivilege.getName(),rbacOrgId));
				}
				if (clientType.equals(ClientType.UI)) {
					identity.getAuthenticationToken().setClientType(
							APIConstants.UI_CLIENT);
					populatePublicCredentials(subject);
				} else {
					identity.getAuthenticationToken().setClientType(
							APIConstants.API_CLIENT);
					populatePublicCredentials(subject);
				}
			}
			else{
				//Loading cloud privileges based on instance id.....
				Integer instanceRoleId = securityDAO.getInstanceRoleId(luserId,instanceId);
				jcpRolePrivileges.addAll(securityDAO.getRolePrivileges(instanceRoleId));
				jcpRolePrivileges.addAll(jcpRole.getPrivileges());
				LOGGER.debug(" jcpRolePrivileges for cloud in JCLoginmodule... "+jcpRolePrivileges);
				Iterator<JCPPrivilege> privilegesIt = jcpRolePrivileges.iterator();
				while (privilegesIt.hasNext()) {
					jcpPrivilege = privilegesIt.next();
					subject.getPrincipals().add(
							new PrivilegePrincipal(jcpPrivilege.getPrivilegeId(), jcpPrivilege.getName(),rbacOrgId,instanceId));
				}
			}
			LOGGER.debug(" LOGIN_SUCCESS value in commit method "+ LOGIN_SUCCESS);
			LOGGER.debug(" end commit() Method of JCLoginModule ");
			return LOGIN_SUCCESS;

		} catch (Exception e) {
			LOGGER.error("Error while updating user privileges", e);
		}
		LOGGER.debug(" LOGIN_SUCCESS value in commit method "+ LOGIN_SUCCESS);
		return LOGIN_FAILURE;
	}

	private void populatePublicCredentials(Subject subject) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start populatePublicCredentials() Method of JCLoginModule ");
		}

		Map<String, Object> userContextMap = new Hashtable<String, Object>();
		userContextMap.put(ISecureSession.PIVOT_PATH_IDENTITY, identity);
		userContextMap.put(ISecureSession.USER_SECURITY_SHORT_INFO,
				usrShortInfo);
		userContextMap.put(ISecureSession.USER_ROLE, jcpRole);
		userContextMap.put(ISecureSession.USER_ROLE_DETAILS, roleDetails);

		userContextMap.put(ISecureSession.USER, user);
		userContextMap.put(ISecureSession.USER_JC_ROLE, userRole);
		userContextMap.put(ISecureSession.USER_ORGANIZATION, organization);
		userContextMap.put(ISecureSession.RBAC_USER_ROLE, rBACUserRole);

		subject.getPublicCredentials().add(userContextMap);
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" end populatePublicCredentials() Method of JCLoginModule ");
		}
	}

	private void populateGuestCredentials(Subject subject) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start populateGuestCredentials() Method of JCLoginModule ");
		}
		userRole = UserRole.DEFAULT;
		JCPPrivilege jcpPrivilege = null;
		List<JCPPrivilege> jcpRolePrivileges = JCRolePrivilegeUtil
				.getRolePrivileges(userRole, null);
		Iterator<JCPPrivilege> privilegesIt = jcpRolePrivileges.iterator();
		while (privilegesIt.hasNext()) {

			jcpPrivilege = privilegesIt.next();
			/**
			 * Get and add the privilege.
			 */
			subject.getPrincipals().add(
					new PrivilegePrincipal(jcpPrivilege.getName()));
		}

		Map<String, Object> userContextMap = new Hashtable<String, Object>();
		userContextMap.put(ISecureSession.USER_JC_ROLE, userRole);
		subject.getPublicCredentials().add(userContextMap);
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" end populateGuestCredentials() Method of JCLoginModule ");
		}
	}

	@Override
	public boolean isValidUser(String clientTypeStr, String companyAcronym,
			String loginName, String password) throws SecurityException {
		AuthenticationInfo authInfo = new AuthenticationInfo();
		List<UserShortInfo> userSearchList = null;
		usrShortInfo = new UserShortInfo();
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start isValidUser() Method of JCLoginModule ");
		}
		try {
			clientType = ClientType.parseClientType(clientTypeStr);
			authInfo.setCompanyAlias(companyAcronym);
			authInfo.setLoginName(loginName);
			authInfo.setPassword(password);
			AuthenticationAPI authAPI = JCAPIFactory.getAuthenticationAPI();
			identity = authAPI.authenticate(authInfo,APIConstants.UI_CLIENT);
			AuthenticationToken authToken = (AuthenticationToken) identity
					.getAuthenticationToken();
			LOGGER
					.debug(" authToken value in JCLoginModule class "
							+ authToken);
			UserAPI userAPI = JCAPIFactory.getUserAPI(authToken);
			UserSearchInfo userSearchInfo = new UserSearchInfo();
			userSearchInfo.setCompanyID(authToken.getCompanyID());
			userSearchInfo.setUserID(authToken.getUserID());
			userSearchList = userAPI.getUsers(userSearchInfo);
			Iterator usrSearchIterator = userSearchList.iterator();

			if (usrSearchIterator.hasNext()) {
				usrShortInfo = (UserShortInfo) usrSearchIterator.next();
			}

		} catch (Exception e) {
			ArrayList<String> errors = new ArrayList<String>();
			LOGGER.error(" Error message in JCLoginModule class "
					+ e.getMessage());
			errors.add(e.getMessage());
			JCDynamicFaultCode dynaFault =  new JCDynamicFaultCode(
					SecurityFaultCode.LOGIN_FAILURE, errors);
			LOGGER.error(" Error message in JCLoginModule class "+e.getClass().getName()+e.toString());
			/*
			 * change for throwing the error message generated during authentication to Active Directory
			 * It catches  the JCAPiException and compare with FaultCode to identify if it is AD Authentication Error 
			 */
			if(e instanceof JCApiException)
			{
				LOGGER.error(" api exception "+SecurityFaultCode.AD_AUTH_ERROR.getCode());
				JCApiException e1 = (JCApiException)e;
				LOGGER.error(" api exception "+e1.getErrorCode().getCode());
				if(e1.getErrorCode().getCode().equals(SecurityFaultCodes.AD_AUTH_ERROR.getCode()))
				{
					errors = new ArrayList<String>();
					errors.add(e1.getMessage());
					dynaFault =  new JCDynamicFaultCode(
							SecurityFaultCode.AD_AUTH_ERROR, errors);	

					LOGGER.error(" inside api exception "+dynaFault.getCode()+" and "+dynaFault.getFaultCode());

					throw new SecurityException(dynaFault);
				}
			}
			
			throw new SecurityException(dynaFault, e.getCause());
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" LOGIN_SUCCESS value in isValidUser() Method "
					+ LOGIN_SUCCESS);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end isValidUser() Method of JCLoginModule ");
		}
		return LOGIN_SUCCESS;
	}

}
