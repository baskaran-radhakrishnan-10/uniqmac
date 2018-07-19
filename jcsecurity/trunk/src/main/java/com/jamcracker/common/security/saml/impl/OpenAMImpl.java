/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.OpenAMImpl 
 * @version 1.0
 * @author 
 * @see
 *
 * <br> ISAMLManager API implementation.
 * 
 ******************************************************/

package com.jamcracker.common.security.saml.impl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import com.iplanet.am.util.SystemProperties;
import com.iplanet.services.util.Crypt;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.jamcracker.common.JCProperties;
import com.jamcracker.common.security.saml.ISAMLManager;
import com.jamcracker.common.security.saml.constants.SAMLConfigConstants;
import com.jamcracker.common.security.saml.dto.SAMLConfiguration;
import com.jamcracker.common.security.saml.exception.IDPNotFoundException;
import com.jamcracker.common.security.saml.exception.SAMLConfigurationException;
import com.jamcracker.common.security.saml.exception.SAMLException;
import com.jamcracker.common.security.saml.exception.SAMLFaultCode;
import com.jamcracker.common.security.saml.impl.util.FederationUtil;
import com.jamcracker.common.security.saml.impl.util.JCECryptUtil;
import com.jamcracker.common.security.saml.impl.util.TemplateReader;
import com.sun.identity.authentication.AuthContext;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.jaxb.entityconfig.EntityConfigElement;
import com.sun.identity.saml2.jaxb.entityconfig.impl.AttributeElementImpl;
import com.sun.identity.saml2.jaxb.entityconfig.impl.SPSSOConfigElementImpl;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;

/**
 * ISAMLManager API implementation.
 * 
 * OPENAMImpl implements SAML functionalities, specific to OPENAM IDP
 * 
 * @author vpkota
 */
public class OpenAMImpl implements ISAMLManager {

	private static final Logger LOG = Logger.getLogger(OpenAMImpl.class);

	/**
	 * This variable holds the Remote IDP metadata configuration details.
	 */
	private String metadataTemplateFile;

	/**
	 * This variable holds IDP (OPENAM) metaData Configuration Details.
	 */
	private String metadataExtendedTemplateFile;

	private SAML2MetaManager saml2MetaManager;

	/**
	 * This variable holds the AMConfig.properties file path. while is set in
	 * the secuirty-application-context.xml
	 */
	private String samlConfigFile;

	/**
	 * This varaible holds the IDP (OPENAM) certificate. while is set in the
	 * secuirty-application-context.xml
	 */
	private String certificateAlias;
	
	/* This variable holds the OpenAM Configuration properites, loaded from
	 * AMConfig.properties in OpenAM server.
	 */
	private static Properties amConfigProp = new Properties();

	/**
	 * This Method Creates a SAML Configuration in OpenaAM
	 * 
	 * @param SAMLConfiguration
	 * @return
	 * @throws SAMLConfigurationException
	 */
	@Override
	public void createSAMLConfig(SAMLConfiguration samlConfig)
			throws SAMLConfigurationException {
		AuthContext lc = null;
		try {
			if (isSAMLIDPAlive()) {
				lc = getAuthContext("/", "DataStore");
				if (login(lc)) {
					
					if (isRealmExist((String) samlConfig.getConfigValue(SAMLConfigConstants.COMPANY_ACR))) {
						FederationUtil
								.updateSAMLFederation(
										(String) samlConfig.getConfigValue(SAMLConfigConstants.COMPANY_ACR),
										(String) samlConfig
												.getConfigValue(SAMLConfigConstants.METADATA),
										createSPMetadata(samlConfig),
										createFromTemplate(
												metadataExtendedTemplateFile,
												createObjectMap(samlConfig)),
										certificateAlias,
										(String) samlConfig
												.getConfigValue(SAMLConfigConstants.URL),
										lc.getSSOToken());
					} else {
						
						FederationUtil
						.createSAMLFederattion(
								(String) samlConfig.getConfigValue(SAMLConfigConstants.COMPANY_ACR),
								(String) samlConfig
										.getConfigValue(SAMLConfigConstants.METADATA),
								createSPMetadata(samlConfig),
								createFromTemplate(
										metadataExtendedTemplateFile,
										createObjectMap(samlConfig)),
								certificateAlias,
								(String) samlConfig
										.getConfigValue(SAMLConfigConstants.URL),
								lc.getSSOToken());
					}
					lc.logout();
				}
			} else {
				throw new IDPNotFoundException(SAMLFaultCode.IDP_SERVER_DOWN);
			}
		} catch (SAMLConfigurationException e) {
			LOG.error("Failes in SAML Configuration", e);
			throw e;
		} catch (Exception e) {
			LOG.error("Failes in SAML Configuration", e);
			throw new SAMLConfigurationException(
					SAMLFaultCode.SAML_CONFIGURATION_FAILED, e);
		}
	}

	/**
	 * This method gets the Login Context
	 * 
	 * @param orgName
	 * @param loginIndexName
	 * @return
	 * @throws SAMLException
	 */
	protected AuthContext getAuthContext(String orgName, String loginIndexName)
			throws SAMLException {
		AuthContext lc = null;
		try {
			LOG.info("getAuthContext : OrgName" + orgName + " LoginIndexName : " + loginIndexName);
			lc = new AuthContext(orgName);
			AuthContext.IndexType indexType = AuthContext.IndexType.MODULE_INSTANCE;
			LOG.info( " IndexType : "  + indexType);
			lc.login(indexType, loginIndexName);
			LOG.debug(loginIndexName + ": Obtained login context");
		} catch (AuthLoginException e) {
			LOG.error("Failed to Obtain Login Contex : ", e);
			throw new SAMLException(SAMLFaultCode.AUTH_LOGIN_FAILED, e);
		}
		return lc;
	}

	/**
	 * This method validates login success or failed
	 * 
	 * @param lc
	 * @return
	 * @throws SAMLException
	 */
	protected boolean login(AuthContext lc) throws SAMLConfigurationException {
		boolean succeed = false;
		;
		try {
			// succeed = false;
			Callback[] callbacks = null;

			// get information requested from module
			while (lc.hasMoreRequirements()) {
				callbacks = lc.getRequirements();
				if (callbacks != null) {
					addLoginCallbackMessage(callbacks);
					lc.submitRequirements(callbacks);
				}
			}

			if (lc.getStatus() == AuthContext.Status.SUCCESS) {
				LOG.debug("Login succeeded.");
				succeed = true;
			} else if (lc.getStatus() == AuthContext.Status.FAILED) {
				LOG.debug("Login failed.");
				throw new SAMLConfigurationException(SAMLFaultCode.LOGIN_FAILED);
			} else {
				LOG.debug("Unknown status: " + lc.getStatus());
			}
		} catch (Exception e) {
			LOG.error(" Login Failed :" + e);
			throw new SAMLConfigurationException(SAMLFaultCode.LOGIN_FAILED, e);
		}

		return succeed;
	}

	/**
	 * This Method validates the UserName And Password through CallbackHandlers
	 * 
	 * @param callbacks
	 * @throws UnsupportedCallbackException
	 */
	private void addLoginCallbackMessage(Callback[] callbacks)
			throws UnsupportedCallbackException {
		int i = 0;
		try {
			for (i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof NameCallback) {
					handleNameCallback((NameCallback) callbacks[i]);
				} else if (callbacks[i] instanceof PasswordCallback) {
					handlePasswordCallback((PasswordCallback) callbacks[i]);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
			throw new UnsupportedCallbackException(callbacks[i], e.getMessage());
		}
	}

	private void handleNameCallback(NameCallback nc) throws IOException {
		String userName = SystemProperties
				.get("com.sun.identity.agents.app.username");
		nc.setName(userName);
	}

	private void handlePasswordCallback(PasswordCallback pc) throws IOException {
		String passwd = null;
		String pw = SystemProperties.get("com.iplanet.am.service.secret");
		String amENCKey = SystemProperties.get("am.encryption.pwd");
		if (amENCKey != null && !"".equals(amENCKey.trim()))
			passwd = JCECryptUtil.decode(pw, amENCKey);
		else
			passwd = Crypt.decode(pw);
		pc.setPassword(passwd.toCharArray());
	}

	/**
	 * This Method validate Request, whether SMAL or NON-SAML
	 * 
	 * @param request
	 * @return
	 * @throws SAMLException
	 */
	@Override
	public boolean validateRequest(HttpServletRequest request)
			throws SAMLException {

		LOG.info("#############validateRequest##############");
		
		if (!isSAMLIDPAlive()) {
			throw new IDPNotFoundException(SAMLFaultCode.IDP_SERVER_DOWN);
	 	}
		SSOToken ssoToken = null;
		SSOTokenManager tokenManager;
		String authType = (String) request.getSession().getAttribute(
				SAMLConfigConstants.AUTH_TYPE);
		LOG.debug("Auth Type : " + authType);
		if (authType != null) {
			// if Request is SAML, then creates and validate the SSO Token, else
			// return the true
			if (SAMLConfigConstants.SAML.equals(authType)) {
				try {
					tokenManager = SSOTokenManager.getInstance();
					ssoToken = tokenManager.createSSOToken(request);
					if ((ssoToken != null)
							&& tokenManager.isValidToken(ssoToken)) {
						return true;
					}
				} catch (SSOException e) {
					LOG.error(" Validating the SAML Request Failed : ", e);
					return false;
				}
			} else {
				return true;
			}
		}
		return false;
	}

	/**
	 * This Method, checks the real is exists or not, if exists then consturucts
	 * remote IDP Login Url and LogOut Url and forward to the IDP server and if
	 * authentication success in IDP the realy the request to the doSAMLLogin
	 * Action. param request,response,companyAcr
	 * 
	 * @return String
	 * @throws SAMLException
	 */
	@Override
	public String  federate(HttpServletRequest request,String companyAcronym)
			throws SAMLException {

		try {
			LOG.info("########### Federate Started #############");
			List<String> spMetaAliases = getMetaManager().getAllHostedServiceProviderMetaAliases(companyAcronym);
			List<String> idpEntities = getMetaManager().getAllRemoteIdentityProviderEntities(companyAcronym);
            LOG.debug(" Size of spMetaAliases :   " + spMetaAliases.size()  + " and Size of idpEntities : " + idpEntities.size());
			if (spMetaAliases != null && spMetaAliases.size() == 0
					&& idpEntities != null && idpEntities.size() == 0) {
				request.getSession().setAttribute(
						SAMLConfigConstants.AUTH_TYPE,
						SAMLConfigConstants.NON_SAML);
				return "";
			}
			String myMetaAlias = spMetaAliases.get(0);
			String partnerEntityID = idpEntities.get(0);
			LOG.debug(" myMetaAlias : " + myMetaAlias + " partnerEntityID : " + partnerEntityID );
			StringBuffer str = new StringBuffer(
					getAMURL(request.getServerName()));
			str.append("/spssoinit?metaAlias=");
			str.append(myMetaAlias).append("&idpEntityID=")
					.append(partnerEntityID).append("&")
					.append(SAML2Constants.BINDING);
			str.append("=HTTP-Artifact").append("&RelayState=")
					.append(getJSDNURL(request))
					.append("/login/doSAMLLogin.action");
			StringBuffer strLogoutURL = new StringBuffer(
					getAMURL(request.getServerName()));
			strLogoutURL.append("/SPSloInit?idpEntityID=");
			strLogoutURL.append(partnerEntityID).append("&idpEntityID=")
					.append(partnerEntityID).append("&")
					.append(SAML2Constants.BINDING);
			strLogoutURL.append("=").append(SAML2Constants.HTTP_REDIRECT)
					.append("&RelayState=").append(getJSDNURL(request))
					.append("/login/doSAMLLogin.action");
			String logoutURL = strLogoutURL.toString();
			request.getSession().setAttribute(
					SAMLConfigConstants.SAML_LOGOUT_URL, logoutURL);
			request.getSession().setAttribute(SAMLConfigConstants.AUTH_TYPE,
					SAMLConfigConstants.SAML);
			
			LOG.debug(" Redirection URL : " + str.toString());
			LOG.info("########### Federate Completed #############");
			return str.toString();
		} catch (Exception e) {
			LOG.error(" Failed in  federate : ", e);
			request.getSession().setAttribute(SAMLConfigConstants.AUTH_TYPE,
					SAMLConfigConstants.NON_SAML);
			return "";

		}

	}

	/**
	 * This Method loads the AMConfigProperties , and Returns the
	 * SAML2MetaManager Object
	 * 
	 * @return
	 * @throws SAMLException
	 */
	protected SAML2MetaManager getMetaManager() throws SAMLException {
 
		try {
			LOG.info("####### getMetaManager() Started#######");
			if (saml2MetaManager == null) {
				// loading the AMConfiguration.properties file
				LOG.debug(" Before Loading the AMConfig.Properties");
				if (!(amConfigProp.size() > 0)) 
					loadAMConfigProperties();
				
				LOG.debug(" Successfully Loadded the AMConfig.Properties");
				SystemProperties.initializeProperties(amConfigProp);
				saml2MetaManager = new SAML2MetaManager();
			}
		}catch (Exception e) {
			saml2MetaManager = null;
			LOG.error("Saml Configuration Failed  : ", e);
			throw new SAMLException(SAMLFaultCode.SAML_CONFIGURATION_FAILED, e);
		}catch (NoClassDefFoundError  e) {
			LOG.error("Failed to initialize error : ", e);
			throw new IDPNotFoundException(SAMLFaultCode.IDP_SERVER_DOWN, e);
		}
		return saml2MetaManager;

	}

	protected String createFromTemplate(String templateFileName, Map parameters)
			throws Exception {

		String template = TemplateReader.getContentTemplate(templateFileName,
				parameters);
		return template;
	}

	/**
	 * This method will return OpenAm port and Protocol values
	 * 
	 * @param storeURL
	 * @return
	 * @throws SAMLConfigurationException
	 */
	protected String getAMURL(String storeURL) {
        StringBuffer amURL=null;
		try {
			LOG.info(" ######### getAMURL ########");
			LOG.debug(" Store URL : " + storeURL);
			//loading the AMConfig.Properties
			if (!(amConfigProp.size() > 0)) 
				loadAMConfigProperties();
			
			SystemProperties.initializeProperties(amConfigProp); 
			String port = amConfigProp.getProperty("com.openam.storeurl.port");
			String protocol = amConfigProp.getProperty("com.openam.storeurl.portocol");
			String contextPath = amConfigProp.getProperty("com.iplanet.am.services.deploymentDescriptor");
			amURL = new StringBuffer(protocol).append("://");
			LOG.debug(" Store Url : "+ storeURL  + "Port Number : " + port + " Protocol : " + protocol + " ContextPath : " + contextPath);
			if(port==null || "".equals(port.trim()))
			{
				amURL.append(storeURL).append(contextPath);
			}else{
				amURL.append(storeURL).append(":").append(port).append(contextPath);
				
			}
			LOG.debug(" AMURL URL : " +  amURL.toString());
		} catch (Exception e) {
			LOG.error(" Error in getAMURL Method :  " ,e);
		} 
		return amURL.toString();
	}
	/**
	 * This method will load  the AMConfigProperties and Construts a URL with SAML OPENAM Properties ,
	 * @return
	 */
	private String getAMURL() {
        StringBuffer amURL=null;
		try {
			LOG.info(" ######### getAMURL ########");
			//loading the AMConfig.Properties
			if (!(amConfigProp.size() > 0)) 
				loadAMConfigProperties();
			
			SystemProperties.initializeProperties(amConfigProp); 
			String protocol = amConfigProp.getProperty("com.iplanet.am.server.protocol");
            String host= amConfigProp.getProperty("com.iplanet.am.server.host");
			String port = amConfigProp.getProperty("com.iplanet.am.server.port");
		    String contextPath = amConfigProp.getProperty("com.iplanet.am.services.deploymentDescriptor");
		    
		    LOG.debug(" Host Name : "+ host  + "Port Number : " + port + " Protocol : " + protocol + " ContextPath : " + contextPath);
			amURL = new StringBuffer(protocol).append("://");
			if(port!=null)
			{
			amURL.append(host).append(":").append(port).append(contextPath);
			}else{
				amURL.append(host).append(contextPath);
			}
			
			LOG.debug(" AMURL URL : " +  amURL.toString());
		} catch (Exception e) {
			LOG.error(" Error in getAMURL Method :  " ,e);
		} 
		return amURL.toString();
	}

	protected String getJSDNURL(HttpServletRequest request) {
		String relayStateUrl = null;
		String protocol = amConfigProp.getProperty("com.openam.storeurl.portocol");
		String port = amConfigProp.getProperty("com.openam.storeurl.port");
		
		if (SAMLConfigConstants.HTTPS_REQUEST.equalsIgnoreCase(protocol)) 
			relayStateUrl = protocol + "://" + request.getServerName() + ":"+ port + request.getContextPath();
		else 
			relayStateUrl = request.getScheme() + "://" + request.getServerName() + ":"+ request.getServerPort() + request.getContextPath();
		
		LOG.debug("relayUrl::"+relayStateUrl);
		 
		return relayStateUrl;
	}

	/**
	 * This Method will create SPMetadata
	 * 
	 * @param samlConfig
	 * @return
	 * @throws SAMLException
	 */

	private String createSPMetadata(SAMLConfiguration samlConfig)
			throws SAMLException {
		Map metaMap = createObjectMap(samlConfig);
		String metadata;
		try {
			metadata = createFromTemplate(metadataTemplateFile, metaMap);
		} catch (Exception e) {
			throw new SAMLException(SAMLFaultCode.SAML_CONFIGURATION_FAILED, e);
		}
		return metadata;
	}

	/**
	 * This Method will create ObjectMap
	 * 
	 * @param samlConfig
	 * @return
	 * @throws SAMLConfigurationException
	 */
	private Map createObjectMap(SAMLConfiguration samlConfig)
			throws SAMLConfigurationException {
		Map<String, Object> metaMap = null;
		try {
			metaMap = new HashMap<String, Object>();
			metaMap.put("realm",
					samlConfig.getConfigValue(SAMLConfigConstants.COMPANY_ACR));
			metaMap.put("amURL", getAMURL((String) samlConfig
					.getConfigValue(SAMLConfigConstants.URL)));
			metaMap.put("attribMap", samlConfig
					.getConfigValue(SAMLConfigConstants.SAML_MAP_FIELD));
			metaMap.put("AuthnRequestsSigned", samlConfig
					.getConfigValue(SAMLConfigConstants.AUTHN_REQUESTS_SIGNED));
		} catch (Exception e) {
			LOG.error("Failed to create ObjectMap : ", e);
			throw new SAMLConfigurationException(
					SAMLFaultCode.SAML_CONFIGURATION_FAILED, e);
		}
		return metaMap;
	}

	public static String readMetaData(String url) throws Exception {

		URL oracle = new URL(url);
		BufferedReader in = new BufferedReader(new InputStreamReader(
				oracle.openStream()));
		StringBuffer result = new StringBuffer();
		String inputLine;
		while ((inputLine = in.readLine()) != null) {
			result.append(inputLine);
		}

		in.close();
		return result.toString();
	}

	/**
	 * This method will check IDPServer isAlive or Not
	 * 
	 * @param request
	 * @return
	 * @throws SAMLException
	 */
	@Override
	public boolean isSAMLIDPAlive() throws SAMLException {
		boolean alive = false;
		try {
			LOG.info("######## isSAMLIDPAlive ########");
			String urlString = getAMURL() + "/isAlive.jsp";
			LOG.debug("URL String : " + urlString);
			if (urlString != null) {
				try {

					URL u = new URL(urlString);
					HttpURLConnection huc = (HttpURLConnection) u
							.openConnection();
					huc.setRequestMethod("GET"); 
					huc.connect();
					int code = huc.getResponseCode();
					LOG.debug("return code:" + code);
					alive = (code == 200);
				} catch (Exception e) {
					LOG.error("Exception while reaching out the isSSAMLIDP URL" , e);
					alive = false;

				}
			}
		} catch (Exception e) {
			LOG.error("#####failed in isSAMLIDPAlive########", e);
			throw new IDPNotFoundException(SAMLFaultCode.IDP_SERVER_DOWN, e);
		}
		return alive;
	}
	
	

	/**
	 * This method Returns the Core Attribute List for particular companyAcronym
	 * and DStoreUrl.
	 * 
	 * @param realmName
	 * @param entityUrl
	 * @return
	 * @throws SAMLConfigurationException
	 */
	private List<String> getEntityCoreAttributes(String realmName,
			String entityUrl) throws SAMLConfigurationException {

		SPSSOConfigElementImpl configElementType = null;
		List<String> coreAttributesList = new ArrayList<String>();

		try {
			LOG.info("#############getEntityCoreAttributes###############");
			EntityConfigElement entityConfig = getMetaManager().getEntityConfig(realmName, entityUrl);
			LOG.debug(" EntityConfig  : " + entityConfig);
			if (entityConfig != null) {
				if (entityConfig
						.getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig() != null
						&& entityConfig
								.getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig()
								.size() > 0) {

					configElementType = (SPSSOConfigElementImpl) entityConfig
							.getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig()
							.get(0);

					List<AttributeElementImpl> attibutes = configElementType
							.getAttribute();

					for (AttributeElementImpl attiElvemt : attibutes)

						if (attiElvemt.getName().equals("attributeMap")) {

							LOG.debug("AtrributeName"
									+ attiElvemt.getValue().get(0).toString());

							coreAttributesList = attiElvemt.getValue();
						}

				}
			}

		} catch (Exception e) {
			throw new SAMLConfigurationException(
					SAMLFaultCode.SAML_CONFIGURATION_FAILED, e);
		}
		LOG.info("#############getEntityCoreAttributes Ends ###############");
		return coreAttributesList;

	}

	/**
	 * In this method we will get EntityUrl ,CoreAttributeList & DownLoadLink
	 * for particular companyAcronym and DStoreUrl.
	 * 
	 * @param SAMLConfiguration
	 *            config
	 * @return
	 * @throws SAMLConfigurationException
	 */
	public SAMLConfiguration getSAMLConfiguration(SAMLConfiguration config)
			throws SAMLConfigurationException {

		SAMLConfiguration samlConfig = null;
		List<String> coreAttributesList = new ArrayList<String>();
		String downLoadLink = null;
		try {
			LOG.info(" #################  getSAMLConfiguration ##############");
			LOG.debug(" companyAcronym :   "
					+ (String) config
							.getConfigValue(SAMLConfigConstants.COMPANY_ACR)
					+ " DStore URl : "
					+ (String) config.getConfigValue(SAMLConfigConstants.URL));
			samlConfig = new SAMLConfiguration();
			if (isSAMLIDPAlive()) {

				// checking isRealmExist
				boolean isRealmExists = isRealmExist((String) config
						.getConfigValue(SAMLConfigConstants.COMPANY_ACR));

				if (isRealmExists) {
					// For Existing User
					// getting entityCoreAttributes
					String spEntityUrl = getAMURL((String) config
							.getConfigValue(SAMLConfigConstants.URL))
							+ "/Consumer/metaAlias/"
							+ (String) config
									.getConfigValue(SAMLConfigConstants.COMPANY_ACR)
							+ "/sp";
					coreAttributesList = getEntityCoreAttributes(
							(String) config
									.getConfigValue(SAMLConfigConstants.COMPANY_ACR),
							spEntityUrl);

					// getting the downloadLink
					downLoadLink = getAMURL((String) config
							.getConfigValue(SAMLConfigConstants.URL))
							+ "/saml2/jsp/exportmetadata.jsp?realm="
							+ (String) config
									.getConfigValue(SAMLConfigConstants.COMPANY_ACR);

					LOG.debug("DownLoadLink  : " + downLoadLink);
					samlConfig.setConfigValue("attributeList",
							coreAttributesList);
					samlConfig.setConfigValue("downLoadLink", downLoadLink);
				} else {
					// For New User
					samlConfig.setConfigValue("attributeList",
							coreAttributesList);
					samlConfig.setConfigValue("downLoadLink", downLoadLink);
				}
			} else {
				LOG.debug("SAML server is down");
				throw new IDPNotFoundException(SAMLFaultCode.IDP_SERVER_DOWN);
			}
		}  catch (SAMLConfigurationException e) {
			LOG.error("Failes in SAML Configuration", e);
			throw e;
		} catch (Exception e) {
			LOG.error("Failes in SAML Configuration", e);
			throw new SAMLConfigurationException(
					SAMLFaultCode.SAML_CONFIGURATION_FAILED, e);
		}

		return samlConfig;
	}

	/**
	 * This method Will check , is Realm Exists or Not
	 */

	private boolean isRealmExist(String companyAcronym) throws SAMLException {

		try {
			LOG.info(" #### isRealmExists ########");
			List<String> spMetaAliases = getMetaManager().getAllHostedServiceProviderMetaAliases(companyAcronym);
			List<String> idpEntities = getMetaManager().getAllRemoteIdentityProviderEntities(companyAcronym);
			if (spMetaAliases != null && spMetaAliases.size() == 0
					&& idpEntities != null && idpEntities.size() == 0) {
				LOG.info(" Realm Doesnot Exists");
				return false;
			}
		} catch (SAML2MetaException e) {
			LOG.error("Failed to check is RealmExist  :", e);
			throw new SAMLException(SAMLFaultCode.SAML_CONFIGURATION_FAILED, e);
		}
		return true;
	}

	/**
	 * This methods load the AMConfig properites from AMConfig.properites 
	 * specified in SAML_CONFIG_PATH in core.properties
	 */
	private void loadAMConfigProperties () throws SAMLException {
		LOG.info("loading AMconfig properties");
		try {
			
			amConfigProp.load(new FileInputStream(JCProperties.getInstance().getProperty("SAML_CONFIG_PATH")));
			
		} catch (FileNotFoundException e) {
			LOG.error("Failed to load the" + samlConfigFile);
			throw new SAMLException(SAMLFaultCode.AMCONFIG_FILE_NOT_FOUND, e);
		} catch (IOException e) {
			LOG.error("Failed to load the" + samlConfigFile);
			throw new SAMLException(SAMLFaultCode.AMCONFIG_FILE_NOT_FOUND, e);
		}
		LOG.debug(" Successfully Loadded the AMConfig.Properties");
	}
	public void setSamlConfigFile(String samlConfigFile) {
		this.samlConfigFile = samlConfigFile;
	}

	public String getMetadataTemplateFile() {
		return metadataTemplateFile;
	}

	public void setMetadataTemplateFile(String metadataTemplateFile) {
		this.metadataTemplateFile = metadataTemplateFile;
	}

	public String getMetadataExtendedTemplateFile() {
		return metadataExtendedTemplateFile;
	}

	public void setMetadataExtendedTemplateFile(
			String metadataExtendedTemplateFile) {
		this.metadataExtendedTemplateFile = metadataExtendedTemplateFile;
	}

	public String getCertificateAlias() {
		return certificateAlias;
	}

	public void setCertificateAlias(String certificateAlias) {
		this.certificateAlias = certificateAlias;
	}

	public static void main(String[] args) throws Exception {
		System.setProperty("PP_CONFIG_HOME", "D://jboss-avalon/pp_config");
		OpenAMImpl samlManager = new OpenAMImpl();
		samlManager.setSamlConfigFile("/saml/AMConfig.properties");
		samlManager.setMetadataTemplateFile("metadata.ftl");
		samlManager.setMetadataExtendedTemplateFile("extended-metadata.ftl");
		samlManager.setCertificateAlias("test");
		SAMLConfiguration config = new SAMLConfiguration();
		config.setConfigValue(SAMLConfigConstants.COMPANY_ACR, "openamsp1.com");
		// config.setConfigValue(SAMLConfigConstants.COMPANY_ID,companyId);
		config.setConfigValue(
				SAMLConfigConstants.METADATA,
				readMetaData("http://www.idp.com:8080/opensso/saml2/jsp/exportmetadata.jsp?realm=RealmIdp"));
		config.setConfigValue(SAMLConfigConstants.URL, "openamsp1.avalonmarket.com");
		config.setConfigValue(SAMLConfigConstants.SAML_MAP_FIELD, "loginName=loginName");
		config.setConfigValue(SAMLConfigConstants.AUTHN_REQUESTS_SIGNED, "false");
		
		//samlManager.isRealmExist("openamidpusecase.com");
		// String entityUrl =
		// "http://openamsp1.avalonmarket.com:8081/opensso/Consumer/metaAlias/openamsp1.com/sp";
		// EntityConfigElement configuration =
		// samlManager.getMetaManager().getEntityConfig("openamsp1.com",
		// entityUrl);

		//String entityUrl = "http://openamsp1.avalonmarket.com:8081/opensso/Consumer/metaAlias/openamsp1.com/sp";
/*		EntityConfigElement configuration = samlManager.getMetaManager()
				.getEntityConfig("openamsp1.com", entityUrl);
		SPSSOConfigElementImpl ssoConfigElement = (SPSSOConfigElementImpl) configuration
				.getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig().get(0);
		List<AttributeElementImpl> attibutes = ssoConfigElement.getAttribute();
		for (AttributeElementImpl attiElvemt : attibutes) {
			// System.out.println("name" + attiElvemt.getName() + "Value" +
			// attiElvemt.getValue());
			if (attiElvemt.getName().equals("attributeMap")) {
				System.out.println("name"
						+ attiElvemt.getValue().get(0).toString());
			}
			// System.out.println("name" + attiElvemt.getName());
			//

		}
*/		// List<String> coreAttributesList = getEntityCoreAttributes (entityUrl,
		// "openamsp1.com");
		/*
		 * SPSSOConfigElementImpl ssoConfigElement =
		 * (SPSSOConfigElementImpl)configuration
		 * .getIDPSSOConfigOrSPSSOConfigOrAuthnAuthorityConfig().get(0);
		 * List<AttributeElementImpl> attibutes =
		 * ssoConfigElement.getAttribute(); for (AttributeElementImpl attiElvemt
		 * : attibutes) { //System.out.println("name" + attiElvemt.getName() +
		 * "Value" + attiElvemt.getValue()); if
		 * (attiElvemt.getName().equals("attributeMap")) {
		 * System.out.println("name" + attiElvemt.getValue().get(0).toString());
		 * } //System.out.println("name" + attiElvemt.getName()); //
		 * 
		 * }
		 */
		samlManager.createSAMLConfig(config);
		System.exit(0);
		// System.out.println(OpenAMImpl.isSAMLAlive("http://www.openamjc-sp1.com:8081/opensso/isAlive.jsp"));
	}
	
	
}
