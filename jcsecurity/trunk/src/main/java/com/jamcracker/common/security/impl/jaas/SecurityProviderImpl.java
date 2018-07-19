/* * Class: JAASSecurityProvider * * Comments for Developers Only: * * Version History: *  * Ver  Date         Who                Release     What and Why * ---  ----------   ----------         -------     --------------------------------------- * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/impl/jaas/JAASSecurityProvider.java>> * 3.0  05/03/2010   Nisha			    1.0	        Added for menu rendering * 4.0  22/11/2011   veena              1.1         Changes made for SSO Implementation * This software is the confidential and proprietary information of Jamcracker, Inc.  * ("Confidential Information").  You shall not disclose such Confidential Information *  and shall use it only in accordance with the terms of the license agreement you  *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights     *  Reserved * * *  ******************************************************/package com.jamcracker.common.security.impl.jaas;import java.security.Policy;import java.util.ArrayList;import java.util.HashMap;import java.util.Hashtable;import java.util.Iterator;import java.util.List;import java.util.Map;import javax.security.auth.Subject;import javax.servlet.http.HttpServletRequest;import com.jamcracker.api.AuthenticationAPI;import com.jamcracker.api.JCAPIFactory;import com.jamcracker.api.UserAPI;import com.jamcracker.api.common.APIConstants;import com.jamcracker.api.common.exception.JCApiException;import com.jamcracker.api.search.UserSearchInfo;import com.jamcracker.common.exception.DynamicFaultCode;import com.jamcracker.common.exception.JCDynamicFaultCode;import com.jamcracker.common.exception.JCFaultCode;import com.jamcracker.common.security.ClientType;import com.jamcracker.common.security.ISessionHandler;import com.jamcracker.common.security.authentication.AuthToken;import com.jamcracker.common.security.authentication.AuthenticationInfo;import com.jamcracker.common.security.authentication.IJCAuthenticationToken;import com.jamcracker.common.security.authentication.JCAuthenticationToken;import com.jamcracker.common.security.authentication.jaas.JAASAuthenticationPrivateToken;import com.jamcracker.common.security.authentication.jaas.JAASConstants;import com.jamcracker.common.security.authentication.jaas.JAASUtil;import com.jamcracker.common.security.authorization.JCPPrivilege;import com.jamcracker.common.security.authorization.JCPRole;import com.jamcracker.common.security.authorization.JCPRoleDetails;import com.jamcracker.common.security.authorization.ResourceConfig;import com.jamcracker.common.security.authorization.jaas.permissions.EventAccessPermission;import com.jamcracker.common.security.authorization.jaas.permissions.FieldAccessPermission;import com.jamcracker.common.security.authorization.jaas.permissions.MenuAccessPermission;import com.jamcracker.common.security.authorization.jaas.permissions.URLAccessPermission;import com.jamcracker.common.security.authorization.jaas.permissions.WidgetAccessPermission;import com.jamcracker.common.security.authorization.jaas.policy.JAASCustomPolicy;import com.jamcracker.common.security.authorization.jaas.policy.PrivilegePrincipal;import com.jamcracker.common.security.constants.JCSecurityConstants;import com.jamcracker.common.security.exception.SecurityException;import com.jamcracker.common.security.exception.SecurityFaultCode;import com.jamcracker.common.security.facade.dao.ISecurityDAO;import com.jamcracker.common.security.facade.dataobject.RBACUserRole;import com.jamcracker.common.security.facade.dataobject.UserRole;import com.jamcracker.common.security.impl.AbstractSecurityProvider;import com.jamcracker.common.security.spec.ISecureSession;import com.jamcracker.common.security.spec.IUserWebSession;import com.jamcracker.common.security.util.SpringConfigLoader;import com.jamcracker.directory.company.facade.CompanyFacade;import com.jamcracker.directory.dataobject.CompanyShortInfo;import com.jamcracker.directory.dataobject.UserInfo;import com.jamcracker.directory.dataobject.UserShortInfo;import com.jamcracker.directory.user.facade.IUserFacade;import com.jamcracker.event.common.IEvent;import com.jamcracker.jcri.FacadeFactory;import com.jamcracker.security.authentication.AuthenticationToken;import com.jamcracker.security.common.exception.SecurityFaultCodes;import com.jamcracker.security.identity.Identity;/** *  * The JAAS security provider implementation. */public class SecurityProviderImpl extends AbstractSecurityProvider {	private static final long serialVersionUID = 448008309767920017L;	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger			.getLogger(SecurityProviderImpl.class.getName());	private static SecurityProviderImpl instance = null;	private ISessionHandler sessionHandler = null;	boolean loginSuccessful = false;	private UserShortInfo usrShortInfo = null;	protected String instanceId;	private Identity identity = null;	public static final boolean LOGIN_SUCCESS = true;	public static final boolean LOGIN_FAILURE = false;	private ClientType clientType = ClientType.UI;	private UserInfo user = null;	private UserRole userRole = null;	private RBACUserRole rBACUserRole = null;	private CompanyShortInfo organization = null;	private JCPRole jcpRole = null;	private JCPRoleDetails roleDetails = null;	protected String userId;	protected String password;	protected String isProxy;	protected int storeCompanyId;	private static final String DEFAULT_LANGUAGE_CODE = "en_US";		private IJCAuthenticationToken jcAuthToken = null;		protected SecurityProviderImpl() {		/**		 * Set JAAS custom policy If this fails we need to check for method		 * interceptors to avoid these api calls.		 */		Policy existingPolicy = java.security.Policy.getPolicy();		if (!(existingPolicy instanceof JAASCustomPolicy)) {			java.security.Policy					.setPolicy(new JAASCustomPolicy(existingPolicy));		}		existingPolicy = java.security.Policy.getPolicy();		if (LOGGER.isDebugEnabled()) {			LOGGER.debug("JAAS policy installed successfully : "					+ existingPolicy);		}	}	public static SecurityProviderImpl getInstance() {		if (instance == null) {			instance = new SecurityProviderImpl();		}		return instance;	}	/**	 * This method will Validates the Authentication Token and loads the Roles	 * and Privilages to the User .	 * 	 * @param authInfo	 * @return	 * @throws SecurityException	 */	public IJCAuthenticationToken jcAuthenticateClient(			AuthenticationInfo authInfo) throws SecurityException {		if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" start jcAuthenticateWebClient() Method of SecurityProviderImpl ");		}		Map<String, Object> loginMap = authInfo.getInfoMap();		IJCAuthenticationToken jcAuthToken = null;		JAASAuthenticationPrivateToken privateToken = null;		Subject subject = new Subject();		try {			LOGGER.debug(" in jcAuthenticateWebClient of SecurityProviderImpl Class ");			if (loginMap != null) {				// This method authenticates the user by obtaining with required				// credentials from a given loginMap				// and Validating the User via PivotPath (authenticate()				// method).if it returns true . then its				// successfully Validates the Authentication Token.				loginSuccessful = isValidUser(loginMap);				LOGGER.debug(" Login Successful : " + loginSuccessful);				// if its true , then its loads the Roles and Privilages of the				// user.				if (loginSuccessful) {					subject = loadRolesAndPrivilegestoUser(loginMap);				}				/**				 * 				 * Authentication successful & update the subject to				 * authentication				 * 				 * token.				 */				privateToken = new JAASAuthenticationPrivateToken(subject,						AUTHENTICATION_SUCCESS);				jcAuthToken = new JCAuthenticationToken(authInfo, privateToken);			}		} catch (SecurityException e) {			LOGGER.error(					"SecurityProviderImpl --> Login Failure in Exception : ", e);			jcAuthToken = JCAuthenticationToken.INVALID_JCAUTH_TOKEN;			throw e;		} catch (Exception e) {			LOGGER.error(					"SecurityProviderImpl --> Login Failure in Exception : ", e);			jcAuthToken = JCAuthenticationToken.INVALID_JCAUTH_TOKEN;			throw new SecurityException(SecurityFaultCode.INVALID_ACCESS, e);		}		if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" end jcAuthenticateWebClient() Method of SecurityProviderImpl ");		}		return jcAuthToken;	}	@Override	public IJCAuthenticationToken authenticate(AuthenticationInfo authInfo)			throws SecurityException {		return jcAuthenticateClient(authInfo);	}	@Override	public boolean canAccessURL(AuthToken authToken,			ResourceConfig resourceCfg) {		if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" start canAccessURL() Method of JAASSecurityProvider ");		}		String urlToAccess = (String) resourceCfg				.getResourceProperty(ResourceConfig.URL_TO_ACCESS);		 if(urlToAccess != null){			URLAccessPermission uRLAccessPermission = new URLAccessPermission(					urlToAccess, null);			Subject tokenSubject = authToken.getSubject();						if(authToken instanceof IJCAuthenticationToken){				jcAuthToken = (IJCAuthenticationToken) authToken;			}						if (jcAuthToken != null 					&& jcAuthToken.isValid()					&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {				JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken						.getAuthPrivateToken();				if (privateToken.hasLoggedIn()) {					uRLAccessPermission.setUserContextMap(privateToken							.getUserContextMap());					tokenSubject = privateToken.getSubject();				}			}			return JAASUtil.isAccessPermitted(tokenSubject,uRLAccessPermission);		}				if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" END canAccessURL() Method of JAASSecurityProvider ");		}		return CANNOT_ACCESS_RESOURCE;	}	@Override	public boolean canAccessEvent(AuthToken authToken,			ResourceConfig resourceCfg) {		if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" start canAccessEvent() Method of JAASSecurityProvider ");		}		IEvent event = (IEvent) resourceCfg				.getResourceProperty(ResourceConfig.EVENT_TO_ACCESS);		String action = resourceCfg.getResourceActionType().getActionType();		if(event != null){			EventAccessPermission eventAccessPermission = new EventAccessPermission(					event, action);			Subject tokenSubject = authToken.getSubject();						if(authToken instanceof IJCAuthenticationToken){				jcAuthToken = (IJCAuthenticationToken) authToken;			}			if (jcAuthToken != null					&& jcAuthToken.isValid()					&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {				JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken						.getAuthPrivateToken();				if (privateToken.hasLoggedIn() && event != null) {										eventAccessPermission.setUserContextMap(privateToken							.getUserContextMap());					tokenSubject = privateToken.getSubject();				}			}							return JAASUtil.isAccessPermitted(tokenSubject,	eventAccessPermission);		}				if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" END canAccessEvent() Method of JAASSecurityProvider ");		}		return CANNOT_ACCESS_RESOURCE;	}	@Override	public boolean canAccessWidget(AuthToken authToken,			ResourceConfig resourceCfg) {		if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" start canAccessEvent() Method of JAASSecurityProvider ");		}		String widgetId = (String) resourceCfg				.getResourceProperty(ResourceConfig.WIDGET_TO_ACCESS);		String action = resourceCfg.getResourceActionType().getActionType(); 		if(widgetId!= null){						Subject tokenSubject = authToken.getSubject();						if(authToken instanceof IJCAuthenticationToken){				jcAuthToken = (IJCAuthenticationToken) authToken;			}						WidgetAccessPermission eventAccessPermission = new WidgetAccessPermission(					widgetId, action, null);			if (jcAuthToken != null					&& jcAuthToken.isValid()					&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {				JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken						.getAuthPrivateToken();				if (privateToken.hasLoggedIn() && widgetId != null) {					eventAccessPermission.setUserContextMap(privateToken							.getUserContextMap());					 tokenSubject = privateToken.getSubject();				}			}		    return JAASUtil.isAccessPermitted(tokenSubject, eventAccessPermission);		}						if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" END canAccessEvent() Method of JAASSecurityProvider ");		}		return CANNOT_ACCESS_RESOURCE;	}	@Override	public boolean canAccessField(AuthToken authToken,			ResourceConfig resourceCfg) {		if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" start canAccessField() Method of JAASSecurityProvider ");		}		String jspURI = (String) resourceCfg				.getResourceProperty(ResourceConfig.JSP_URI_TO_ACCESS);		String fieldName = (String) resourceCfg				.getResourceProperty(ResourceConfig.FIELD_TO_ACCESS);		String action = resourceCfg.getResourceActionType().getActionType();		if(fieldName != null){			Subject tokenSubject = authToken.getSubject();			if(authToken instanceof IJCAuthenticationToken){				jcAuthToken = (IJCAuthenticationToken) authToken;			} 			FieldAccessPermission fieldAccessPermission = new FieldAccessPermission(					jspURI, fieldName, action, null);			if (jcAuthToken != null					&& jcAuthToken.isValid()					&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {				JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken						.getAuthPrivateToken();				if (privateToken.hasLoggedIn() && jspURI != null						&& fieldName != null && action != null) {					fieldAccessPermission.setUserContextMap(privateToken							.getUserContextMap());					tokenSubject = privateToken.getSubject();				}			} 				return JAASUtil.isAccessPermitted(tokenSubject, fieldAccessPermission);		}			if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" end canAccessField() Method of JAASSecurityProvider ");		}		return CANNOT_ACCESS_RESOURCE;	}	@Override	public boolean canAccessMenu(AuthToken authToken,			ResourceConfig resourceCfg) {		if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" start canAccessMenu() Method of JAASSecurityProvider ");		}		String menuToAccess = (String) resourceCfg				.getResourceProperty(ResourceConfig.MENU_TO_ACCESS);				if(menuToAccess != null){						Subject tokenSubject = authToken.getSubject();			if(authToken instanceof IJCAuthenticationToken){				jcAuthToken = (IJCAuthenticationToken) authToken;			} 			MenuAccessPermission menuAccessPermission = new MenuAccessPermission(					menuToAccess, null);			LOGGER.debug(" in canAccessMenu() method "					+ jcAuthToken					+ " and jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken "					+ (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)					+ " and jcAuthToken.isValid() " + jcAuthToken.isValid());						if (jcAuthToken != null					&& jcAuthToken.isValid()					&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {				JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken						.getAuthPrivateToken();				if (privateToken.hasLoggedIn() && menuToAccess != null) {					menuAccessPermission.setUserContextMap(privateToken							.getUserContextMap());					tokenSubject = privateToken.getSubject();				}			} 		    return JAASUtil.isAccessPermitted(tokenSubject, menuAccessPermission);		}						if (LOGGER.isDebugEnabled()) {			LOGGER.debug(" END canAccessMenu() Method of JAASSecurityProvider ");		}		return CANNOT_ACCESS_RESOURCE;	}	@Override	public ISessionHandler getSessionHandler() {		return sessionHandler;	}	@Override	public void setSessionHandler(ISessionHandler sessionHandler) {		this.sessionHandler = sessionHandler;	}	public IUserWebSession getWebSession(HttpServletRequest request,			AuthToken authToken) {		LOGGER.debug("Entered into getWebSession() of JAASSecurityProvider ");		IJCAuthenticationToken jcAuthToken = null;		String handlerClassName = (String) request				.getAttribute(ISessionHandler.SESSION_HANDLER_CLASS_KEY_NAME);		IUserWebSession userWebSession = null;		Map<String, Object> propertyMap = new HashMap<String, Object>();		if(authToken instanceof IJCAuthenticationToken){			jcAuthToken = (IJCAuthenticationToken) authToken;		}		if (jcAuthToken != null && jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken) {			JAASAuthenticationPrivateToken jaasPrivateToken = (JAASAuthenticationPrivateToken) jcAuthToken					.getAuthPrivateToken();			propertyMap = jaasPrivateToken.getUserContextMap();		}		/*		 * Creating JSDN Web session there is no session handler class key		 * name present in request		 */		LOGGER.info("Handler Class is " + handlerClassName);		if (handlerClassName == null) {			userWebSession = sessionHandler.createUserWebSession(request,					jcAuthToken, propertyMap);		} else {			try {				Class handlerClass = Class.forName(handlerClassName);				ISessionHandler sessionHandler = (ISessionHandler) handlerClass						.newInstance();				userWebSession = sessionHandler.createUserWebSession(						request, authToken,						propertyMap);			} catch (Exception e) {				LOGGER.error(						"Exception in  JAASSecurityProvider  while getting Web Session ",						e);			}		}		LOGGER.debug("End of getWebSession() of JAASSecurityProvider ");		return userWebSession;			}	/**	 * This method Validates the Authentication Token.	 * 	 * @param credentials	 * @return	 * @throws SecurityException	 */	private boolean isValidUser(Map<String, Object> credentials)			throws SecurityException {		List<UserShortInfo> userSearchList = null;		AuthenticationToken authToken = null;		usrShortInfo = new UserShortInfo();		LOGGER.debug(" ######## isValidUser() Method of SecurityProviderImpl Started ######## ");		try {			AuthenticationAPI authAPI = JCAPIFactory.getAuthenticationAPI();			instanceId = (String) credentials.get(JAASConstants.INSTANCE_ID);			LOGGER.debug(" Instance ID : " + instanceId);			/*			 * if login is for cloud instance, instance id is not null and			 * 			 * logged in user authentication token used for to validating the			 * token,			 * 			 * to check api request is valid or not.			 */			if (instanceId == null					|| JAASConstants.EMPTY_STRING.equals(instanceId)) {				/*				 * Author: Dheeraj Nagwani Reason: Checking the existing				 * authToken. If present and valid, using the same. This is				 * required for AD/SAML based Enterprises to be able to be able				 * to do proxy.				 * 				 * Without this, it will try to re-authenticate the user with				 * the external server (AD or IDP) and fail as the password in				 * the DB may not match with the external server (AD or IDP).				 * 				 * This will also work for a normal reseller / marketplace admin				 * trying to proxy. It will not re-authenticate if the AuthToken				 * from the marketplace is still valid.				 */				identity = (Identity) credentials.get(JAASConstants.IDENTITY);				if (identity != null) {					authToken = identity.getAuthenticationToken();				}				boolean isValidToken = false;				try {					if (authToken != null) {						isValidToken = authAPI.isValidToken(authToken);					}				} catch (Exception e) {					// Adding try/catch block because isValidToken method does					// not return false if					// the token is invalid. Instead it throws an exception!!					LOGGER.debug("Error while validating passed in token. Authenticating again. If the user is AD or SAML enabled, then this will fail");				}				if (!isValidToken) {					identity = authAPI.authenticate(credentials,							APIConstants.UI_CLIENT);					authToken = identity.getAuthenticationToken();				}				credentials.put(JAASConstants.LOGIN_NAME,						identity.getLoginName());			} else {				authToken = (AuthenticationToken) credentials						.get(JAASConstants.JC_AUTH_TOKEN);				if (!authAPI.isValidToken(authToken)) {					LOGGER.error("Invalid token to get instance details");					throw new SecurityException(SecurityFaultCode.INVALID_TOKEN);				}			}			LOGGER.debug(" authToken value in SecurityProviderImpl  "					+ authToken);			UserAPI userAPI = JCAPIFactory.getUserAPI(authToken);			UserSearchInfo userSearchInfo = new UserSearchInfo();			userSearchInfo.setCompanyID(authToken.getCompanyID());			userSearchInfo.setUserID(authToken.getUserID());			userSearchList = userAPI.getUsers(userSearchInfo);			Iterator<UserShortInfo> usrSearchIterator = userSearchList					.iterator();			if (usrSearchIterator.hasNext()) {				usrShortInfo = (UserShortInfo) usrSearchIterator.next();			}			LOGGER.debug(" SuccessFully Authenticated the User Token "					+ LOGIN_SUCCESS);			LOGGER.debug(" ####### isValidUser() Method of SecurityProviderImpl  is Completed #######");		}catch (JCApiException e) {						LOGGER.error(" JCApiException occurred while validating user details", e);			ArrayList errors = new ArrayList(); 						if(e.getErrorCode().getCode().equals(SecurityFaultCodes.AD_AUTH_ERROR.getCode()) && e.getFaultCode() instanceof DynamicFaultCode)			{								LOGGER.error(" Error message in SecurityProviderImpl class " + e.getMessage());                errors.add(e.getMessage());                JCDynamicFaultCode dynaFault =  new JCDynamicFaultCode(SecurityFaultCode.LOGIN_FAILURE, errors);                                                                LOGGER.debug("dynamic exception encountered, fault code::"+dynaFault.getFaultCode());                                throw new SecurityException(dynaFault, e.getCause());			} else {				throw new SecurityException(JCFaultCode.getFaultCode(e.getFaultCode().toString()), e);			}					}catch (Exception e) {			LOGGER.error("Failed to Validate User Token", e);						throw new SecurityException(SecurityFaultCode.LOGIN_FAILURE,					e.getCause());		}		return LOGIN_SUCCESS;	}	/**	 * This method Loads the Roles and Privilages to the User.	 * 	 * @param loginMap	 * @return	 * @throws SecurityException	 */	private Subject loadRolesAndPrivilegestoUser(Map<String, Object> loginMap)			throws SecurityException {		LOGGER.info(" ########start loadRolesAndPrivilegestoUser() Method of SecurityProviderImpl############ ");		ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader				.getBean(JCSecurityConstants.JC_SECURITY_DAO);		Subject subject = new Subject();		try {			user = new UserInfo();			// temporarily fix for bugid=12359 , needed permanent fix for bugid			// 12536 , Proxy Should happen with MarketPlace companyID/Super			// Admin CompanyID.			if (loginMap.get(JAASConstants.PARENT_COMPANY_ID) != null) {				storeCompanyId = ((Integer) loginMap						.get(JAASConstants.PARENT_COMPANY_ID)).intValue();			}			IUserFacade userFacade = FacadeFactory.getInstance().getUserFacade();			int luserId = usrShortInfo.getUserID();			int pivotPathroleId = usrShortInfo.getUserRoleID();			LOGGER.debug("User ID   : " + userId					+ "  PivotPath  User role  ID :   " + pivotPathroleId);			user.setUserID(luserId);			user = userFacade.getUserInfo(luserId);			int orgId = -1;			// rbacOrgId will have user company id which is used to pass as			// constructor argument for PrivilegePrincipal			int rbacOrgId = -1;			if (loginMap.get(JAASConstants.IS_PROXY) != null					&& ((Boolean) loginMap.get(JAASConstants.IS_PROXY))							.booleanValue() == true) {				orgId = (Integer) loginMap.get(JAASConstants.E_ORG_COMPANY_ID);				rbacOrgId = (Integer) loginMap						.get(JAASConstants.E_ORG_COMPANY_ID);				LOGGER.debug(" In Proxy -- > OrgId  : " + orgId						+ "  rbacOrgId : " + rbacOrgId);			} else {				orgId = user.getCompanyID();				rbacOrgId = user.getCompanyID();				LOGGER.debug("  OrgId  : " + orgId + "  rbacOrgId : "						+ rbacOrgId);			}			CompanyFacade companyFacade = FacadeFactory.getInstance()					.getCompanyFacade();			organization = companyFacade.getCompanyShortInfo(orgId);			jcpRole = securityDAO.getRole(pivotPathroleId);			roleDetails = securityDAO.getRoleDetails(pivotPathroleId,					DEFAULT_LANGUAGE_CODE);			userRole = UserRole.extractRole(pivotPathroleId);			LOGGER.debug("  Organization  : " + organization + "  JcpRole : "					+ jcpRole + " UserRole" + userRole);			JCPPrivilege jcpPrivilege = null;			List<JCPPrivilege> jcpRolePrivileges = new ArrayList<JCPPrivilege>();			/*			 * instanceId is not null then populate permission list in subject			 * for cloud instances			 */			if (instanceId == null					|| JAASConstants.EMPTY_STRING.equals(instanceId)) {				// Loading jsdn privileges.....				if (loginMap.get(JAASConstants.IS_PROXY) != null						&& ((Boolean) loginMap.get(JAASConstants.IS_PROXY))								.booleanValue() == true) {					orgId = (Integer) loginMap							.get(JAASConstants.E_ORG_COMPANY_ID);					rbacOrgId = (Integer) loginMap							.get(JAASConstants.E_ORG_COMPANY_ID);					rBACUserRole = securityDAO.getProxyAclRoleId(orgId);				} else if (JAASConstants.GUEST_USER_ID == luserId) {					rBACUserRole = securityDAO							.getGuestAclRoleId(storeCompanyId);					/*					 * Set rbacOrgId as store company id If guest user is logged					 * in					 * 					 * since the privileges are defined at store level for guest					 * user					 */					rbacOrgId = storeCompanyId;				} else					rBACUserRole = securityDAO.getAclRoleId(luserId);				if (rBACUserRole != null) {					LOGGER.debug(" ACL Role is available");					jcpRolePrivileges.addAll(securityDAO							.getRolePrivileges(rBACUserRole.getRoleId()));				} else					rBACUserRole = new RBACUserRole();				jcpRolePrivileges.addAll(jcpRole.getPrivileges());				LOGGER.debug(" jcpRolePrivileges for jsdn in SecurityProviderImpl... "						+ jcpRolePrivileges);				Iterator<JCPPrivilege> privilegesIt = jcpRolePrivileges						.iterator();				while (privilegesIt.hasNext()) {					jcpPrivilege = privilegesIt.next();					/**					 * 					 * Get and add the privilege.					 */					subject.getPrincipals().add(					new PrivilegePrincipal(jcpPrivilege.getPrivilegeId(), jcpPrivilege.getName(), rbacOrgId));				}				if (clientType.equals(ClientType.UI)) {					identity.getAuthenticationToken().setClientType(					APIConstants.UI_CLIENT);					populatePublicCredentials(subject);				} else {					identity.getAuthenticationToken().setClientType(					APIConstants.API_CLIENT);					populatePublicCredentials(subject);				}			}			else {				// Loading cloud privileges based on instance id.....				Integer instanceRoleId = securityDAO.getInstanceRoleId(luserId,						instanceId);				jcpRolePrivileges.addAll(securityDAO						.getRolePrivileges(instanceRoleId));				jcpRolePrivileges.addAll(jcpRole.getPrivileges());				LOGGER.debug(" jcpRolePrivileges for cloud in SecurityProviderImpl... "						+ jcpRolePrivileges);				Iterator<JCPPrivilege> privilegesIt = jcpRolePrivileges						.iterator();				while (privilegesIt.hasNext()) {					jcpPrivilege = privilegesIt.next();					subject.getPrincipals().add(							new PrivilegePrincipal(jcpPrivilege.getPrivilegeId(), jcpPrivilege.getName(),									rbacOrgId, instanceId));				}			}			LOGGER.debug(" LOGIN_SUCCESS value in commit method "					+ LOGIN_SUCCESS);			LOGGER.debug("######### End commit() Method of SecurityProviderImpl ###########");			LOGGER.debug(" LOGIN_SUCCESS value in commit method "					+ LOGIN_SUCCESS);			return subject;		} catch (Exception e) {			LOGGER.error("Error while fetching the  user privileges", e);			throw new SecurityException(SecurityFaultCode.LOGIN_FAILURE,					e.getCause());		}	}	/**	 * This method populates the user roles and privileges into userContext	 * @param subject	 */	private void populatePublicCredentials(Subject subject) {		LOGGER.debug(" ###### populatePublicCredentials() Method of SecurityProviderImpl  Started #######");		Map<String, Object> userContextMap = new Hashtable<String, Object>();		userContextMap.put(ISecureSession.PIVOT_PATH_IDENTITY, identity);		userContextMap.put(ISecureSession.USER_SECURITY_SHORT_INFO,				usrShortInfo);		userContextMap.put(ISecureSession.USER_ROLE, jcpRole);		userContextMap.put(ISecureSession.USER_ROLE_DETAILS, roleDetails);		userContextMap.put(ISecureSession.USER, user);		userContextMap.put(ISecureSession.USER_JC_ROLE, userRole);		userContextMap.put(ISecureSession.USER_ORGANIZATION, organization);		userContextMap.put(ISecureSession.RBAC_USER_ROLE, rBACUserRole);		subject.getPublicCredentials().add(userContextMap);		LOGGER.debug("####### populatePublicCredentials() Method of SecurityProviderImpl Completed ###### ");	}}