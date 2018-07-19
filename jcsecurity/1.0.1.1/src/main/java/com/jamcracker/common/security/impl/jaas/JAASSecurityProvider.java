/*
 * Class: JAASSecurityProvider
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/impl/jaas/JAASSecurityProvider.java>>
 * 3.0  05/03/2010   Nisha			    1.0	        Added for menu rendering
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
package com.jamcracker.common.security.impl.jaas;

import java.security.Policy;
import java.util.ArrayList;
import java.util.StringTokenizer;

import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.exception.JCDynamicFaultCode;
import com.jamcracker.common.security.ClientType;
import com.jamcracker.common.security.ISessionHandler;
import com.jamcracker.common.security.authentication.AuthenticationInfo;
import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.authentication.JCAuthenticationToken;
import com.jamcracker.common.security.authentication.jaas.JAASAuthenticationPrivateToken;
import com.jamcracker.common.security.authentication.jaas.JAASConstants;
import com.jamcracker.common.security.authentication.jaas.JAASUtil;
import com.jamcracker.common.security.authentication.jaas.callback.JAASCallbackHandler;
import com.jamcracker.common.security.authentication.jaas.cfg.JAASConfiguration;
import com.jamcracker.common.security.authorization.ResourceConfig;
import com.jamcracker.common.security.authorization.jaas.permissions.EventAccessPermission;
import com.jamcracker.common.security.authorization.jaas.permissions.FieldAccessPermission;
import com.jamcracker.common.security.authorization.jaas.permissions.MenuAccessPermission;
import com.jamcracker.common.security.authorization.jaas.permissions.URLAccessPermission;
import com.jamcracker.common.security.authorization.jaas.permissions.WidgetAccessPermission;
import com.jamcracker.common.security.authorization.jaas.policy.JAASCustomPolicy;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.exception.SecurityFaultCode;
import com.jamcracker.common.security.impl.AbstractSecurityProvider;
import com.jamcracker.common.security.spec.IUserWebSession;
import com.jamcracker.event.common.IEvent;

/**
 * The JAAS security provider implementation.
 */
public class JAASSecurityProvider extends AbstractSecurityProvider {
	
	private ISessionHandler sessionHandler = null;

	private static final long serialVersionUID = 448008309767920017L;

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(JAASSecurityProvider.class.getName());


	public JAASSecurityProvider() {

		/**
		 * Set JAAS custom policy If this fails we need to check for method
		 * interceptors to avoid these api calls.
		 */
		Policy existingPolicy = java.security.Policy.getPolicy();

		if (!(existingPolicy instanceof JAASCustomPolicy)) {
			java.security.Policy
					.setPolicy(new JAASCustomPolicy(existingPolicy));
		}

		/**
		 * Set JAAS login module configuration Set the current login
		 * configuration to be used by the LoginContext.
		 */
		Configuration existingConfig = Configuration.getConfiguration();
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" what is the existingConfig in JAASSecurityProvider "
					+ existingConfig);
		}
		if (!(existingConfig instanceof JAASConfiguration)) {
			Configuration
					.setConfiguration(new JAASConfiguration(existingConfig));
		}

		existingPolicy = java.security.Policy.getPolicy();
		existingConfig = Configuration.getConfiguration();
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("JAAS policy installed successfully : "
					+ existingPolicy);
			LOGGER.debug("JAAS configuration installed successfully : "
					+ existingConfig);
		}
	}

/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.impl.AbstractSecurityProvider#canAccessURL(com.jamcracker.common.security.authentication.JCAuthenticationToken, com.jamcracker.common.security.authorization.ResourceConfig)
 */
	@Override
	public boolean canAccessURL(IJCAuthenticationToken jcAuthToken,
			ResourceConfig resourceCfg) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start canAccessURL() Method of JAASSecurityProvider ");
		}
		String urlToAccess = (String) resourceCfg
				.getResourceProperty(ResourceConfig.URL_TO_ACCESS);
		jcAuthToken.isValid();
		if (jcAuthToken != null
				&& jcAuthToken.isValid()
				&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {

			JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken
					.getAuthPrivateToken();

			if (privateToken.hasLoggedIn() && urlToAccess != null) {

				URLAccessPermission uRLAccessPermission =new URLAccessPermission(urlToAccess,null);
				uRLAccessPermission.setUserContextMap(privateToken.getUserContextMap());
				return JAASUtil.isAccessPermitted(privateToken.getSubject(),uRLAccessPermission);
			}
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END canAccessURL() Method of JAASSecurityProvider ");
		}
		return CANNOT_ACCESS_RESOURCE;
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.impl.AbstractSecurityProvider#canAccessWidget(com.jamcracker.common.security.authentication.JCAuthenticationToken, com.jamcracker.common.security.authorization.ResourceConfig)
 */
	@Override
	public boolean canAccessWidget(IJCAuthenticationToken jcAuthToken,
			ResourceConfig resourceCfg) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start canAccessEvent() Method of JAASSecurityProvider ");
		}
		String widgetId =  (String) resourceCfg.getResourceProperty(ResourceConfig.WIDGET_TO_ACCESS);
		String action = resourceCfg.getResourceActionType().getActionType();

		if (jcAuthToken != null
				&& jcAuthToken.isValid()
				&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {

			JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken
					.getAuthPrivateToken();

			if (privateToken.hasLoggedIn() && widgetId != null) {

				WidgetAccessPermission eventAccessPermission =new WidgetAccessPermission(widgetId,action,null);
				eventAccessPermission.setUserContextMap(privateToken.getUserContextMap());
				return JAASUtil
						.isAccessPermitted(privateToken.getSubject(),eventAccessPermission);
			}
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" END canAccessEvent() Method of JAASSecurityProvider ");
		}
		return CANNOT_ACCESS_RESOURCE;
	}
	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.impl.AbstractSecurityProvider#canAccessEvent(com.jamcracker.common.security.authentication.JCAuthenticationToken, com.jamcracker.common.security.authorization.ResourceConfig)
	 */
		@Override
		public boolean canAccessEvent(IJCAuthenticationToken jcAuthToken,
				ResourceConfig resourceCfg) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER
						.debug(" start canAccessEvent() Method of JAASSecurityProvider ");
			}
			IEvent event = (IEvent) resourceCfg
					.getResourceProperty(ResourceConfig.EVENT_TO_ACCESS);
			String action = resourceCfg.getResourceActionType().getActionType();

			if (jcAuthToken != null
					&& jcAuthToken.isValid()
					&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {

				JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken
						.getAuthPrivateToken();

				if (privateToken.hasLoggedIn() && event != null) {

					EventAccessPermission eventAccessPermission =new EventAccessPermission(event,action);
					eventAccessPermission.setUserContextMap(privateToken.getUserContextMap());
					return JAASUtil
							.isAccessPermitted(privateToken.getSubject(),eventAccessPermission);
				}
			}
			if (LOGGER.isDebugEnabled()) {
				LOGGER
						.debug(" END canAccessEvent() Method of JAASSecurityProvider ");
			}
			return CANNOT_ACCESS_RESOURCE;
		}

/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.impl.AbstractSecurityProvider#canAccessField(com.jamcracker.common.security.authentication.JCAuthenticationToken, com.jamcracker.common.security.authorization.ResourceConfig)
 */
	@Override
	public boolean canAccessField(IJCAuthenticationToken jcAuthToken,
			ResourceConfig resourceCfg) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start canAccessField() Method of JAASSecurityProvider ");
		}
		String jspURI = (String) resourceCfg
				.getResourceProperty(ResourceConfig.JSP_URI_TO_ACCESS);
		String fieldName = (String) resourceCfg
				.getResourceProperty(ResourceConfig.FIELD_TO_ACCESS);
		String action = resourceCfg.getResourceActionType().getActionType();

		if (jcAuthToken != null
				&& jcAuthToken.isValid()
				&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {

			JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken
					.getAuthPrivateToken();

			if (privateToken.hasLoggedIn() && jspURI != null
					&& fieldName != null && action != null) {
				FieldAccessPermission fieldAccessPermission =new FieldAccessPermission(jspURI,fieldName,action,null);
				fieldAccessPermission.setUserContextMap(privateToken.getUserContextMap());
				return JAASUtil.isAccessPermitted(privateToken.getSubject(),fieldAccessPermission);
			}

		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" end canAccessField() Method of JAASSecurityProvider ");
		}
		return CANNOT_ACCESS_RESOURCE;
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.spec.IAuthenticationProvider#authenticate(com.jamcracker.common.security.authentication.AuthenticationInfo)
 */
	@Override
	public IJCAuthenticationToken authenticate(AuthenticationInfo authInfo)
			throws SecurityException {
		/**
		 * The LoginContext uses the current thread's class loader to load the
		 * "login module" class. If class loader is not set for current thread
		 * then it may not be able to load the "login module."
		 * 
		 * The login module & this security provider classes are loaded by,
		 * 
		 * org.jboss.mx.loading.UnifiedClassLoader3@3b4dca
		 * 
		 * -- JCLoginModule.class.getClassLoader() --
		 * this.getClass().getClassLoader()
		 * 
		 * When the call comes as part of web request then its loaded by,
		 * 
		 * org.jboss.web.tomcat.service.WebCtxLoader$ENCLoader@1c62719
		 * 
		 * -- Thread.currentThread().getContextClassLoader();
		 * 
		 * 
		 * NOTE : As LoginContext tries to load "login module" using current
		 * thread's conext class loader, it may not find login module. So set
		 * the current threads class loader accordingly.
		 */
		// ClassLoader curClsLdr =
		// Thread.currentThread().getContextClassLoader();
		// try {
		// Thread.currentThread().setContextClassLoader(this.getClass().getClassLoader());
		return jcAuthenticateCore(authInfo);
		// }
		// finally {
		// //Thread.currentThread().setContextClassLoader(curClsLdr);
		// }

	}

	public IJCAuthenticationToken jcAuthenticateCore(AuthenticationInfo authInfo)
			throws SecurityException {

		if (authInfo.getClientType().equals(ClientType.UI)) {
			return jcAuthenticateClient(authInfo);
		}

		return JCAuthenticationToken.INVALID_JCAUTH_TOKEN;
	}

	public IJCAuthenticationToken jcAuthenticateClient(
			AuthenticationInfo authInfo) throws SecurityException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" start jcAuthenticateWebClient() Method of JAASSecurityProvider ");
		}
		IJCAuthenticationToken jcAuthToken = null;
		JAASAuthenticationPrivateToken privateToken = null;

		try {
			LOGGER.debug(" in jcAuthenticateWebClient of JAASSecurity Class ");
			JAASCallbackHandler handler = new JAASCallbackHandler(
					authInfo.getClientType().toString(), authInfo
							.getCompanyAcronym(), authInfo.getUserName(),
					authInfo.getPassword(),authInfo.isProxy()?JAASConstants.YES:JAASConstants.NO,
					String.valueOf(authInfo.getStoreCompanyId()),
					authInfo.getInstanceId(),String.valueOf(authInfo.getProxiedCompanyId()));

			LoginContext loginContext = new LoginContext(
					JAASConstants.LOGIN_MODULE_NAME_OLD, handler);

			/**
			 * Do login.
			 */
			loginContext.login();

			/**
			 * Authentication successful & update the subject to authentication
			 * token.
			 */
			privateToken = new JAASAuthenticationPrivateToken(loginContext
					.getSubject(), AUTHENTICATION_SUCCESS);

			jcAuthToken = new JCAuthenticationToken(authInfo, privateToken);

		} catch (LoginException le) {
			LOGGER
					.error("JAASSecurityProvider class Login Failure in LoginException : "
							+ le);
			/*
			 * It catches  the LoginException and tokenize and compare with FaultCode to identify if it is AD Authentication Error 
			 * If it is AD Error then it throws as SecurityException with same FaultCode 
			 * 
			 */
			if(le.getMessage().indexOf("||")>0)
			{
				StringTokenizer st= new StringTokenizer(le.getMessage(),"||");
				if(st.hasMoreTokens())
				{
					String st1 = st.nextToken();
					String st2 = st.nextToken();
					if(st1.equals(SecurityFaultCode.AD_AUTH_ERROR.getCode()))
					{

						ArrayList errors = new ArrayList<String>();
						errors.add(st2);				
						throw new SecurityException(new JCDynamicFaultCode(
								SecurityFaultCode.AD_AUTH_ERROR, errors));
					}
				}
			}
			throw new SecurityException(SecurityFaultCode.LOGIN_FAILURE, le);
		} catch (Exception e) {
			LOGGER
					.error("JAASSecurityProvider class Login Failure in Exception : "
							+ e);
			jcAuthToken = JCAuthenticationToken.INVALID_JCAUTH_TOKEN;
			throw new SecurityException(SecurityFaultCode.INVALID_ACCESS, e);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug(" end jcAuthenticateWebClient() Method of JAASSecurityProvider ");
		}
		/**
		 * Set private token to the authentication token.
		 */
		return jcAuthToken;

	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.impl.AbstractSecurityProvider#getWebSession(javax.servlet.http.HttpSession, com.jamcracker.common.security.authentication.JCAuthenticationToken)
 */
	@Override
	public IUserWebSession getWebSession(HttpServletRequest request,
			IJCAuthenticationToken jcAuthToken) {
		LOGGER.debug("Entered into getWebSession() of JAASSecurityProvider "); 
		if (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken) {
			String handlerClassName = (String)request.getAttribute(ISessionHandler.SESSION_HANDLER_CLASS_KEY_NAME);
			IUserWebSession userWebSession = null;
			JAASAuthenticationPrivateToken jaasPrivateToken = (JAASAuthenticationPrivateToken) jcAuthToken.getAuthPrivateToken();
			/* Creating JSDN Web session there is no session handler class key name present in request*/
			LOGGER.info("Handler Class is " + handlerClassName);
			
			if(handlerClassName == null){
				userWebSession= sessionHandler.createUserWebSession(request,jcAuthToken, jaasPrivateToken
								.getUserContextMap());
			}
			else{
				try {
						Class handlerClass   = Class.forName(handlerClassName); 
						ISessionHandler sessionHandler = (ISessionHandler)handlerClass.newInstance();
						userWebSession= sessionHandler.createUserWebSession(request,jcAuthToken, jaasPrivateToken
								.getUserContextMap());
				} catch (Exception e) {
					LOGGER.error("Exception in  JAASSecurityProvider  while getting Web Session ",e);	
				}
			}
			LOGGER.debug("End of getWebSession() of JAASSecurityProvider ");
			return userWebSession;
		}

		/**
		 * Found unknown authentication private token. So nothing to handle,
		 * just ignore.
		 */
		return null;
	}
	
	/**
	 * This method is used to check whether the menu is accessible or not.
	 * @param jcAuthToken
	 * @param resourceCfg
	 * @return
	 */
	public boolean canAccessMenu(IJCAuthenticationToken jcAuthToken,	ResourceConfig resourceCfg) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start canAccessMenu() Method of JAASSecurityProvider ");
		}
		String menuToAccess = (String) resourceCfg.getResourceProperty(ResourceConfig.MENU_TO_ACCESS);
		jcAuthToken.isValid();
		
		LOGGER.debug(" in canAccessMenu() method "+jcAuthToken+" and jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken "+(jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)+" and jcAuthToken.isValid() "+jcAuthToken.isValid());
		
		if (jcAuthToken != null
				&& jcAuthToken.isValid()
				&& (jcAuthToken.getAuthPrivateToken() instanceof JAASAuthenticationPrivateToken)) {

			JAASAuthenticationPrivateToken privateToken = (JAASAuthenticationPrivateToken) jcAuthToken
					.getAuthPrivateToken();

			if (privateToken.hasLoggedIn() && menuToAccess != null) {

				MenuAccessPermission menuAccessPermission =new MenuAccessPermission(menuToAccess,null);
				menuAccessPermission.setUserContextMap(privateToken.getUserContextMap());
				return JAASUtil.isAccessPermitted(privateToken.getSubject(),menuAccessPermission);
			}
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" END canAccessMenu() Method of JAASSecurityProvider ");
		}
		return CANNOT_ACCESS_RESOURCE;
	}

	@Override
	public ISessionHandler getSessionHandler() {
		return sessionHandler;
	}

	@Override
	public void setSessionHandler(ISessionHandler sessionHandler) {
		this.sessionHandler = sessionHandler;
	}	
}
