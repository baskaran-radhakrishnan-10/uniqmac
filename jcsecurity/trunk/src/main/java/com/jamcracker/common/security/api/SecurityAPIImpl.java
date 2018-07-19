/*
 * Class: SecurityAPIImpl
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/api/SecurityAPIImpl.java>>
 * 3.0  04/03/2010   Nisha			    1.0	        Added for menu rendering  
 * 3.0  o9/10/2012   Santhosh                       Added Code for  Vulnarabality Fix
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
package com.jamcracker.common.security.api;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.api.JCAPIFactory;
import com.jamcracker.common.security.UserSessionFactory;
import com.jamcracker.common.security.authentication.AuthenticationInfo;
import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.authentication.JCAuthenticationToken;
import com.jamcracker.common.security.authorization.JCPMenu;
import com.jamcracker.common.security.authorization.ResourceActionType;
import com.jamcracker.common.security.authorization.ResourceConfig;
import com.jamcracker.common.security.authorization.ResourceType;
import com.jamcracker.common.security.authorization.jaas.policy.DBPermissionAdapter;
import com.jamcracker.common.security.authorization.jaas.policy.PermissionAdapter;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.exception.SecurityFaultCode;
import com.jamcracker.common.security.facade.dao.ISecurityDAO;
import com.jamcracker.common.security.facade.dataobject.RBACUserRole;
import com.jamcracker.common.security.saml.ISAMLManager;
import com.jamcracker.common.security.saml.constants.SAMLConfigConstants;
import com.jamcracker.common.security.saml.exception.IDPNotFoundException;
import com.jamcracker.common.security.saml.exception.SAMLException;
import com.jamcracker.common.security.saml.exception.SAMLFaultCode;
import com.jamcracker.common.security.spec.ISecurityProvider;
import com.jamcracker.common.security.spec.IUserWebSession;
import com.jamcracker.common.security.util.SpringConfigLoader;
import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.IValidator;
import com.jamcracker.common.security.validator.exception.BrokenAutherizationException;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.impl.ValidationObserver;
import com.jamcracker.event.common.IEvent;
import com.jamcracker.jcri.FacadeFactory;
import com.jamcracker.security.authentication.AuthenticationToken;
import com.jamcracker.security.facade.SecurityFacade;
import com.jamcracker.security.identity.Identity;

/**
 * The entry point to security framework. We can inject security provider
 * implementation using Spring DI.
 */

public class SecurityAPIImpl extends SecurityBaseAPI implements ISecurityAPI {
	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(SecurityAPIImpl.class.getName());
	/**
	 * This variable holds the SAMLProvider implementation class
	 */
	private static ISAMLManager samlManager;
	
	
	
	/**
	 * This variable holds the validator observer implementation class
	 */
	private ValidationObserver validationObserver;
	


	/**
	 * Set the security provider to default security provider.
	 */
	ISecurityProvider securityProvider = (ISecurityProvider) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_PROVIDER);
	ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_DAO);
	public SecurityAPIImpl() throws Exception{
		this(JCAuthenticationToken.INVALID_JCAUTH_TOKEN);
	}

	
	
	protected SecurityAPIImpl(IJCAuthenticationToken jcAuthToken)
			throws Exception {
			super(jcAuthToken);

	}
/*
 * 
 * (non-Javadoc)
 * @see com.jamcracker.common.security.api.ISecurityAPI#authenticate(com.jamcracker.common.security.authentication.AuthenticationInfo)
 */
	public IJCAuthenticationToken authenticate(AuthenticationInfo authInfo)
			throws SecurityException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" authenticate() method IN SecurityAPIImpl ");
		}
		return securityProvider.authenticate(authInfo);
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.api.ISecurityAPI#canAccessURL(java.lang.String)
	 */
	public boolean canAccessURL(String url) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" START canAccessURL() method of SecurityAPIImpl ");
		}
		ResourceConfig resourceCfg = new ResourceConfig(
				ResourceType.URL_RESOURCE, ResourceActionType.URL_ACCESS);
		resourceCfg.setResourceProperty(ResourceConfig.URL_TO_ACCESS, url);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END canAccessURL() method of SecurityAPIImpl ");
		}
		return securityProvider.canAccessResource(jcAuthToken, resourceCfg);
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.api.ISecurityAPI#canAccessEvent(com.jamcracker.event.common.IEvent)
 */
	public boolean canAccessEvent(IEvent event) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" START canAccessEvent() method of SecurityAPIImpl ");
		}
		ResourceConfig resourceCfg = new ResourceConfig(
				ResourceType.EVENT_RESOURCE, ResourceActionType.EVENT_EXECUTE);
		resourceCfg.setResourceProperty(ResourceConfig.EVENT_TO_ACCESS, event);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END canAccessEvent() method of SecurityAPIImpl ");
		}
		return securityProvider.canAccessResource(jcAuthToken, resourceCfg);
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.api.ISecurityAPI#canAccessWidget(java.lang.String)
	 */
		public boolean canAccessWidget(String widgetId) {
			LOGGER.debug(" START canAccessWidget() method of SecurityAPIImpl ");
			ResourceConfig resourceCfg = new ResourceConfig(
					ResourceType.WIDGET_RESOURCE, ResourceActionType.WIDGET_ACCESS);
			resourceCfg.setResourceProperty(ResourceConfig.WIDGET_TO_ACCESS, widgetId);
			LOGGER.debug(" END canAccessWidget() method of SecurityAPIImpl ");
			return securityProvider.canAccessResource(jcAuthToken, resourceCfg);
		}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.api.ISecurityAPI#canMaskEvent(com.jamcracker.event.common.IEvent)
 */
	public boolean canMaskEvent(IEvent event) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" Start canMaskEvent() method of SecurityAPIImpl ");
		}
		ResourceConfig resourceCfg = new ResourceConfig(
				ResourceType.EVENT_RESOURCE, ResourceActionType.EVENT_MASK);
		resourceCfg.setResourceProperty(ResourceConfig.EVENT_TO_ACCESS, event);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END canMaskEvent() method of SecurityAPIImpl ");
		}
		return securityProvider.canAccessResource(jcAuthToken, resourceCfg);
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.api.ISecurityAPI#canViewField(java.lang.String, java.lang.String)
 */
	public boolean canViewField(String jspURI, String fieldName) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start canViewField() method of SecurityAPIImpl ");
		}
		ResourceConfig resourceCfg = new ResourceConfig(
				ResourceType.FIELD_RESOURCE, ResourceActionType.FIELD_VIEW);
		resourceCfg.setResourceProperty(ResourceConfig.JSP_URI_TO_ACCESS,
				jspURI);
		resourceCfg.setResourceProperty(ResourceConfig.FIELD_TO_ACCESS,
				fieldName);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END canViewField() method of SecurityAPIImpl ");
		}
		return securityProvider.canAccessResource(jcAuthToken, resourceCfg);
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.api.ISecurityAPI#canEditField(java.lang.String, java.lang.String)
 */
	public boolean canEditField(String jspURI, String fieldName) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start canEditField() method of SecurityAPIImpl ");
		}
		ResourceConfig resourceCfg = new ResourceConfig(
				ResourceType.FIELD_RESOURCE, ResourceActionType.FIELD_EDIT);
		resourceCfg.setResourceProperty(ResourceConfig.JSP_URI_TO_ACCESS,
				jspURI);
		resourceCfg.setResourceProperty(ResourceConfig.FIELD_TO_ACCESS,
				fieldName);
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end canEditField() method of SecurityAPIImpl ");
		}
		return securityProvider.canAccessResource(jcAuthToken, resourceCfg);
	}
	
	/**
	 * This method used to get the whole menus from the database.
	 * 
	 */
	public List<JCPMenu> getAccessibleMenuList(IJCAuthenticationToken autoken) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" START getAccesibleMenuList() method of SecurityAPIImpl ");
		}
		ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_DAO);
		List<JCPMenu> accessibleMenuList = new ArrayList<JCPMenu>();
		
		try {
			List<JCPMenu> menuList = securityDAO.getAllMenus();
			for (int i = 0; i < menuList.size(); i++) {
				JCPMenu menu = menuList.get(i);
				boolean flag = canAccessMenu(menu.getResourceName(), autoken);
				if (flag) {
					accessibleMenuList.add(menu);
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" Size of accessibleMenuList" + accessibleMenuList.size());
		}
		return accessibleMenuList;
	}
	
	/**
	 * This method is used to check whether the current menu is Accessible or not.
	 * @param menu
	 * @param autoken 
	 * @return
	 */
	public boolean canAccessMenu(String menu, IJCAuthenticationToken autoken) {
		ResourceConfig resourceCfg = new ResourceConfig(
				ResourceType.MENU_RESOURCE, ResourceActionType.MENU_VIEW);
		resourceCfg.setResourceProperty(ResourceConfig.MENU_TO_ACCESS, menu);
		
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END canAccessMenu() method of SecurityAPIImpl ");
		}
		jcAuthToken = autoken;
		return securityProvider.canAccessResource(jcAuthToken, resourceCfg);
	}
	
	/**
	 * This method is used to get RBACUserRole information for user
	 * @param int userId
	 * @return RBACUserRole
	 */
	public RBACUserRole getRBACUserRole(int userId) throws SecurityException {
		LOGGER.debug("Start of getRBACUserRole method of SecurityAPIImpl ::userId:"+userId);
		RBACUserRole rBACUserRole = null;
		try {
			rBACUserRole= securityDAO.getAclRoleId(userId);
		} catch (SecurityException e) {
			LOGGER.error("SecurityException in  getRBACUserRole of SecurityAPIImpl: ", e);
			throw e;
		}
		LOGGER.debug(" End of getRBACUserRole method of SecurityAPIImpl ::userId:"+userId);
		return rBACUserRole;
	}
	
	/*
	 * Method used to delete the ActionPermission Map from HashTable. So that for the next time login we can reload the permissions from DB.
	 * Currently its loading for every restart. This we can call 
	 * 
	 * @author Surendra Babu
	 */
	public void removeActorPermission(int companyId){
		LOGGER.debug("Entered into method removeActorPermission in SecurityAPIImpl");
		PermissionAdapter permissionAdapter = DBPermissionAdapter.getInstance();
		permissionAdapter.removeActorPermission(companyId);
		LOGGER.debug("End of method removeActorPermission in SecurityAPIImpl");
	}
	
	/**
	 * 	This method authenticateSAMLRequest the store url for saml stores, which involves 
	 *  checks SAML IDP server is alive or not, and Validates whether the request is for SAML or not, 
	 *  if the request is for saml then it fedarate the request to SAML IDP Login.
	 *  and after authentication ,it will return the Redirected URL.
	 */
	public String authenticateSAMLRequest(HttpServletRequest request, String companyAcronym, int companyId) throws SAMLException {
		String federateResponse = JCSecurityConstants.EMPTY;
		String loginModuleName = null;
		try {
			
			LOGGER.info("####### checkingPostAuthenticationUrl #############");
			
			IUserWebSession userWebSession = UserSessionFactory.getInstance().getActiveUserSession(request);

			// Fetching the Login Module Name , either LDAP or SAML
			if (userWebSession.getProperty(JCSecurityConstants.LOGIN_MODULE_NAME) == null) {
				loginModuleName =  getLoginModuleName(companyId);
				userWebSession.setProperty(JCSecurityConstants.LOGIN_MODULE_NAME, loginModuleName);
			}
			
			//check proxy scenario
			boolean isProxy=((IJCAuthenticationToken)userWebSession.getAuthenticationToken()).getAuthInfo().isProxy();
			if(!isProxy)
			{
				String proxyValue=request.getParameter("proxied");
				isProxy=proxyValue==null? false : true;
			}
			
			LOGGER.debug("isProxy::"+isProxy+"loginModuleName::"+loginModuleName);
			
			if (loginModuleName != null && loginModuleName.contains(SAMLConfigConstants.SAML_LOGIN_MODULE_NAME) && (!isProxy)) {

				if (!samlManager.validateRequest(request) ) {
						federateResponse = samlManager
								.federate(request, companyAcronym);
				}
			
			}
				
			LOGGER.info("####### End of checkingPostAuthenticationUrl #############");
		}catch (SecurityException e) {
			LOGGER.error(" Failed to fetch the Login ModuleName : " ,  e);
			throw new SAMLException(e.getFaultCode());
		} catch (Exception e) {
			LOGGER.error("Failed to Validate the request : ", e);
			throw new IDPNotFoundException(SAMLFaultCode.IDP_SERVER_DOWN);
		}
		
		return federateResponse;
	}
	
	/**
	 *  This method will return the  Login Module Name , either LDAP or SAML
	 */
	private String getLoginModuleName(int companyId) throws SecurityException
	{
		LOGGER.info(" ###### getLoginModuleName ####### ");
		LOGGER.debug(" getLoginModuleName --> CompanyId :  " + companyId);
		List<String> loginModuleNamesList = null;
		String loginModuleName = null;
		try {
			loginModuleNamesList = securityDAO.getAuthLoginModuleList(companyId);
			if(loginModuleNamesList.size()>0)
			{
				Iterator<String> it = loginModuleNamesList.iterator();
				while (it.hasNext()) {
					loginModuleName = (String) it.next();
				}
			}
			LOGGER.debug("loginModuleName::"+loginModuleName);
		} catch (SecurityException e) {
			LOGGER.error(" Failed to fetch the Login ModuleName : " ,  e);
			throw e;
		}
		
		return loginModuleName;
	}

	
	
	
	
	
	
	
	/**
	 * This method validates all response content from server . 
	 * if any content in the response has cross site scripting data, it will clean that xss script from the response.  
	 * @param responseContent
	 * @param pageUrl
	 * @return String
	 * @throws ValidatorException 
	 */
	public String xssResponseScanner(String responseContent,String pageUrl) throws ValidatorException{
		String responseString="";
		responseString=((ValidationHelper)SpringConfigLoader.getBean(JCSecurityConstants.VALIDATION_HELPER_BEAN)).xssResponseSanitizer(responseContent, pageUrl);
		return responseString;
	}
	
	/**
	 * Get the Xss Response Filter Enabled Url List
	 * 
	 * @return List<String> urlList
	 * 
	 */
	public List<String> getXssResponseFilterUrlList() {
		//IValidator validator = getVulnerabalityValidator();
		return ((ValidationHelper)SpringConfigLoader.getBean(JCSecurityConstants.VALIDATION_HELPER_BEAN)).xssResponseFilterUrlList;
	}
	
	

	
	

	/**
	 * This methods returns the SAMLProvider implementation (OpenAMImpl)
	 * object reference.
	 */
	public ISAMLManager getSamlManager() {
		return samlManager;
	}

   /**
    * This methods sets the SAMLProvider implementation object reference
    * while initiating SecuirtyImpl bean in security-applicationcontext.xml 
    * @param samlManager
    */
	public static void setSamlManager(ISAMLManager samlManager) {
		SecurityAPIImpl.samlManager = samlManager;
	}

	


	/**
	 * This method generate the token for the given credential
	 * @param loginName
	 * @param password
	 * @param tenant
	 * @return token
	 * @throws SecurityException
	 */	
	@Override
	public String authenticate(String loginName, String password, String tenant) throws SecurityException {
		
		AuthenticationToken authenticationToken = null;
		SecurityFacade securityFacade = null;
		String tokenStr = null;
		
		try {
			securityFacade = FacadeFactory.getInstance().getSecurityFacade();
			authenticationToken = getAuthenticationToken(loginName, password, tenant);
			tokenStr = securityFacade.getTokenString(authenticationToken); //getTokenString from AuthenticationToken
			LOGGER.debug("Token string from AuthenticationToken"+ tokenStr);
		} catch(SecurityException e) {
			LOGGER.error("getAuthenticationToken failed: ", e);
			throw e;
		} catch (Exception e) {
			LOGGER.error("Error creating the token", e);
			throw new SecurityException(SecurityFaultCode.USER_UNAUTHORIZED, e);
		}
		return tokenStr;
	}
	
	/**
	 * This method generate AuthenticationToken for the given  credential
	 * @param loginName
	 * @param password
	 * @param tenant
	 * @return AuthenticationToken
	 * @throws SecurityException
	 */
	private AuthenticationToken getAuthenticationToken(String loginName, String password, String tenant) throws SecurityException {
		AuthenticationToken authenticationToken = null;
		try {
			com.jamcracker.api.security.AuthenticationInfo authInfo = new com.jamcracker.api.security.AuthenticationInfo();
			authInfo.setCompanyAlias(tenant);
			authInfo.setLoginName(loginName);
			authInfo.setPassword(password);
			Identity identity = JCAPIFactory.getAuthenticationAPI().authenticate(authInfo);
			authenticationToken = identity.getAuthenticationToken();
		} catch (Exception e) {
			LOGGER.error("Error creating the token", e);
			throw new SecurityException(SecurityFaultCode.UNAUTHORIZED_TO_ACCESS, e);
		}
		return authenticationToken;
	}



	@Override
	public Boolean startRequestScanForVulnerability(HttpServletRequest request)
			throws ValidatorException {
		return ((ValidationObserver)SpringConfigLoader.getBean("validationObserver")).startScan(request);
	}



	


}
