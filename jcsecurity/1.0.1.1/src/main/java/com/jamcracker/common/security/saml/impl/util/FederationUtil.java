/*************************************************** *  * This software is the confidential and proprietary information of Jamcracker, Inc.  * ("Confidential Information").  You shall not disclose such Confidential Information *  and shall use it only in accordance with the terms of the license agreement you  *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights     *  Reserved * * @ClassName com.jamcracker.common.security.saml.util.FederationUtil * @version 1.0 * @author  * @see * * <br> OpenAm common utility methods. *  ******************************************************/package com.jamcracker.common.security.saml.impl.util;

import java.io.BufferedReader;import java.io.InputStream;import java.io.InputStreamReader;import java.util.HashMap;import java.util.List;import java.util.Map;import org.apache.log4j.Logger;import com.iplanet.sso.SSOToken;import com.jamcracker.common.JCProperties;import com.jamcracker.common.security.saml.constants.SAMLConfigConstants;import com.jamcracker.common.security.saml.exception.SAMLConfigurationException;import com.jamcracker.common.security.saml.exception.SAMLFaultCode;import com.sun.identity.cli.CLIConstants;import com.sun.identity.cli.CLIException;import com.sun.identity.cli.CLIRequest;import com.sun.identity.cli.CommandManager;import com.sun.identity.cli.StringOutputWriter;import com.sun.identity.cot.COTConstants;import com.sun.identity.cot.CircleOfTrustManager;import com.sun.identity.saml2.common.SAML2Exception;import com.sun.identity.saml2.jaxb.entityconfig.EntityConfigElement;import com.sun.identity.saml2.jaxb.metadata.EntityDescriptorElement;import com.sun.identity.saml2.meta.SAML2MetaManager;import com.sun.identity.saml2.meta.SAML2MetaUtils;

public class FederationUtil {
	private static Logger LOG = Logger.getLogger(FederationUtil.class);
	/**	 * This method will Create a Store Configuration in OPENAM	 * @param realm	 * @param remoteMetaData	 * @param spMetadataTemplate	 * @param spExtendedTemplate	 * @param certificateName	 * @param storeURL	 * @param ssoToken	 * @throws SAMLConfigurationException	 */
	static public void createSAMLFederattion(String realm,			String remoteMetaData, String spMetadataTemplate,			String spExtendedTemplate, String certificateName, String storeURL,			SSOToken ssoToken) throws SAMLConfigurationException {
		createRealmAndCot(realm, ssoToken);
		createDataStore(realm, ssoToken);
		createCookieDomain(storeURL, ssoToken);
		createHostedSP(realm, spMetadataTemplate,spExtendedTemplate, certificateName, ssoToken);
		createRemoteIDp(realm, remoteMetaData);
	} 	/**	 * This method deletes and re-create the hosted SP and remote IDP configuration.	 * @param realm	 * @param remoteMetaData	 * @param spMetadataTemplate	 * @param spExtendedTemplate	 * @param certificateName	 * @param storeURL	 * @param ssoToken	 * @throws SAMLConfigurationException	 */	public static void updateSAMLFederation(String realm,			String remoteMetaData, String spMetadataTemplate,			String spExtendedTemplate, String certificateName, String storeURL,			SSOToken ssoToken) throws SAMLConfigurationException {				LOG.info("updateSAMLFederation method starts");				deleteRemoteIDP(realm);				createRemoteIDp(realm, remoteMetaData);				deleteHostedSP(realm, spMetadataTemplate, ssoToken);				createHostedSP(realm, spMetadataTemplate,spExtendedTemplate, certificateName, ssoToken);				LOG.info("updateSAMLFederation method Ends");			}
   /*    * OpenSSO Enterprise also requires a data store for its user data:     * The Data Store authentication module allows a user to authenticate against one or more of a realm's     * identity data stores (depending on the authentication process configuration).    * If you are deploying multiple OpenAM instances in a multiple server deployment,     * all instances must access the same Directory Server.     */

	private static void createDataStore(String realm, SSOToken ssoToken) throws SAMLConfigurationException {
		try {						LOG.info("######## Creation of Data Store Started #########");			
			StringOutputWriter outputWriter = new StringOutputWriter();						String idRepoImplClass = JCProperties.getInstance().getProperty(SAMLConfigConstants.SAML_SUN_IDREPO_IMPL_CLASS);
			String arg[] = {
					"update-datastore",
					"--realm",
					"/"+realm,
					"--name",
					"embedded",
					"--attributevalues",
					"sunIdRepoClass=" + idRepoImplClass,										"sun-idrepo-ldapv3-config-authid="+realm};
        	CLIRequest req = null;
			Map env = new HashMap();						env.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER, outputWriter);
			env.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");
			env.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			CommandManager cmd = new CommandManager(env);
			req = new CLIRequest(null, arg, ssoToken);
			cmd.addToRequestQueue(req);
			cmd.serviceRequestQueue();						LOG.debug("Data store create reponse"+outputWriter.getMessages());						LOG.info("######## Creation of Data Store Completed #########::");
		} catch (CLIException e) {
			LOG.error("Failed to Create Data Store :  " ,e);			throw new SAMLConfigurationException(SAMLFaultCode.CREATE_DATA_STORE_FAILED,e);
		}
	}
   /**    * This method Creates a Configuration in  RemoteIDP with realm and Metadata     * @param realm    * @param metaData    * @throws SAMLConfigurationException    */
	private static void createRemoteIDp(String realm, String metaData) throws SAMLConfigurationException{
		try {			LOG.info("###### Creation of Remote IDP Starts#######");						LOG.debug(" Realm Name : " + realm  + "  MetaData  "  + metaData) ;						String remoteIDPEntityID = null;
			String defaultOrg = realm;
			String endEntityDescripotorTag = "</EntityDescriptor>";
			int metastartIdx = metaData.indexOf("<EntityDescriptor");
			int metaEndIndx = metaData.indexOf(endEntityDescripotorTag,	metastartIdx);
			String metaXML = metaData.substring(metastartIdx, metaEndIndx+ endEntityDescripotorTag.length());
			LOG.debug("  MetaData XML  : "   +  metaXML);
			SAML2MetaManager metaManager = new SAML2MetaManager();
			EntityDescriptorElement idpdescriptor = (EntityDescriptorElement) SAML2MetaUtils.convertStringToJAXB(metaXML);
			remoteIDPEntityID = idpdescriptor.getEntityID();
			LOG.debug( " RemoteIDPEntity ID : "  + remoteIDPEntityID);
			metaManager.createEntityDescriptor(defaultOrg, idpdescriptor);
			CircleOfTrustManager cof = new CircleOfTrustManager();
			cof.addCircleOfTrustMember(realm, "cot",COTConstants.SAML2, remoteIDPEntityID);						LOG.info("###### Creation of Remote IDP Completed #######");		} catch (Exception e) {			LOG.error("Failed to Create RemoteIDP : " + e);			throw new SAMLConfigurationException(SAMLFaultCode.CREATE_REMOTE_IDP_FAILED,e);		}       return;
	}		/**	 * This method deletes the RemoteIDP configuration for given realm.	 * @param realm	 * @throws SAMLConfigurationException	 */	private static void deleteRemoteIDP (String realm) throws SAMLConfigurationException {		LOG.info("deleteRemoteIDP methods Starts");		try {						SAML2MetaManager metaManager = new SAML2MetaManager();						List<String> idpEntities = metaManager.getAllRemoteIdentityProviderEntities(realm);						String entityId  = idpEntities.get(0);						LOG.debug("deletes the remoteIDP::"+entityId+"configuration of realm::"+realm);						if (entityId != null)				metaManager.deleteEntityDescriptor(realm, entityId);					} catch (SAML2Exception e) {						LOG.error("Failed to delete the remoteIDP configuration", e);						throw new SAMLConfigurationException(SAMLFaultCode.DELETE_IDP_FAILED, e);		}	}		/**	 * This methods deletes the Hosted SP configuration, for given realm	 * @param realm	 * @param metaXML	 * @param ssoToken	 * @throws SAMLConfigurationException	 */	private static void deleteHostedSP(String realm, String metaXML,			SSOToken ssoToken) throws SAMLConfigurationException {		LOG.info("deleteHostedSP method starts");		try {						SAML2MetaManager metaManager = new SAML2MetaManager();						EntityDescriptorElement descriptor = (EntityDescriptorElement) SAML2MetaUtils					.convertStringToJAXB(metaXML);			String hostedSPEntityID = descriptor.getEntityID();						LOG.debug("deleting the hosted sp::"+hostedSPEntityID+"configuration fo realm::"+realm);						metaManager.deleteEntityDescriptor(realm, hostedSPEntityID);					} catch(Exception e) {						LOG.error("Error occured while deleting the hosted SP");						throw new SAMLConfigurationException(SAMLFaultCode.DELETE_HOSTED_SP_FAILED, e);					}		LOG.info("deleteHostedSP method Ends");	}		
	/**	 * Creates Hosted Service Provider for realm.	 */	private static void createHostedSP(String realm, String metaXML,			String extendedXML, String certificateName, SSOToken ssoToken)			throws SAMLConfigurationException {		String result = null;		CommandManager cmd = null;		CLIRequest req = null;
	      		  try {						  LOG.info("####### Creation of HostedSP Started##########");			  			  LOG.debug(" Realm Name : " + realm  + " Certificate Name : " + certificateName);
			   StringOutputWriter outputWriter = new StringOutputWriter();			   String[] arg = { "create-metadata-templ", "--entityid",
					realm,
					"--serviceprovider", "/"+realm+"/sp", // Realm_Demo is the
					};
			Map env = new HashMap();						env.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER, outputWriter);		
			env.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.federation.cli.FederationManager");
			env.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			cmd = new CommandManager(env);
			req = new CLIRequest(null, arg, ssoToken);
			cmd.addToRequestQueue(req);
			cmd.serviceRequestQueue();
			result = outputWriter.getMessages();

			String endEntityDescriptortag = null;
			int metaStartindex = 0;
			int metaEndIndex = 0;
			endEntityDescriptortag = "</EntityDescriptor>";
			metaStartindex = result.indexOf("<EntityDescriptor");
			metaEndIndex = result.indexOf(endEntityDescriptortag,metaStartindex);
			// parsing extended metadata
			String endEntityConfigTag = "</EntityConfig>";
			int extendStartIdx = result.indexOf("<EntityConfig ");
			int extendEndIdx = result.indexOf(endEntityConfigTag,
					extendStartIdx);
			String hostedSPEntityID = null;
			SAML2MetaManager metaManager = new SAML2MetaManager();	
			EntityDescriptorElement descriptor = (EntityDescriptorElement) SAML2MetaUtils.convertStringToJAXB(metaXML);
			hostedSPEntityID = descriptor.getEntityID();
			metaManager.createEntityDescriptor(realm, descriptor);
			EntityConfigElement extendConfigElm = (EntityConfigElement) SAML2MetaUtils.convertStringToJAXB(extendedXML);
			metaManager.createEntityConfig(realm, extendConfigElm);					CircleOfTrustManager cof = new CircleOfTrustManager();
			cof.addCircleOfTrustMember(realm, "cot",COTConstants.SAML2, hostedSPEntityID);						LOG.debug("####### Creation of HostedSP Completed##########");		} catch (Exception e) {			LOG.error("Failed to Create HostedSP",e);			throw new SAMLConfigurationException(SAMLFaultCode.CREATE_HOSTED_SP_FAILED,e);		}
		return;
	}
   /**    *  This method created a realm name(a unique Identity) and COT(Circle of Trust) in SAMLIDP    * @param realm    * @param ssoToken    * @return    * @throws SAMLConfigurationException    */
	private static String createRealmAndCot(String realm, SSOToken ssoToken) throws SAMLConfigurationException{
		String result=null;				CommandManager cmd = null;		CLIRequest req = null;				try {            LOG.info("#########Creating  Realm And Cot Started#########" );                        LOG.debug("@@REALM NAME  : "  + realm );            			StringOutputWriter outputWriter = new StringOutputWriter();			// Realm-Creation
			String[] arg1 = { "create-realm", "--realm", realm };
			Map env1 = new HashMap();			
			env1.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER, outputWriter);
			env1.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");
			env1.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");			cmd = new CommandManager(env1);
			req = new CLIRequest(null, arg1, ssoToken);
			cmd.addToRequestQueue(req);
			cmd.serviceRequestQueue();						result = outputWriter.getMessages();
     		// Cot-Creation under realm			// Cot means Circle of Trust			//A circle of trust, previously referred to as an authentication domain, is a federation of any number of service providers 			//(and at least one identity provider) with whom principals can transact business in a secure and apparently seamless environment. 			//To create and populate a circle of trust, you first create an entity to hold the metadata (configuration information that defines a particular 			//identity service architecture) for each provider that will become a member of the circle of trust. 						LOG.debug("Creation of COT under Realm :" + realm);						CommandManager cmd2 = null;			CLIRequest req2 = null;
			String arg2[] = { "create-cot", "--cot", "cot", "--realm", realm };
			Map env2 = new HashMap();						env2.put(CLIConstants.ARGUMENT_LOCALE, java.util.Locale.ENGLISH);
			env2.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER, outputWriter);			env2.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.federation.cli.FederationManager");
			env2.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			cmd = new CommandManager(env2);
			req2 = new CLIRequest(null, arg2, ssoToken);
			cmd.addToRequestQueue(req2);
			cmd.serviceRequestQueue();
			result = outputWriter.getMessages();
			LOG.debug("  RealmAndCot Message : "  + result);
			arg1 = new String[] {"set-realm-svc-attrs",
			         "--realm",realm,
			         "--servicename","iPlanetAMAuthService",
			         "--attributevalues","iplanet-am-auth-dynamic-profile-creation=ignore"};
			Map env3 = new HashMap();						env3.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER, outputWriter);
			env3.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");
			env3.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			cmd = new CommandManager(env3);
			CLIRequest req3 = new CLIRequest(null, arg1, ssoToken);
			cmd.addToRequestQueue(req3);
			cmd.serviceRequestQueue();						LOG.debug("#########Creation of  Realm And Cot Completed #########" );					} catch (Exception e) {			LOG.error(" Failed to  create Realm And Cot : " ,e);			throw new SAMLConfigurationException(SAMLFaultCode.CREATION_REALM_COT_FAILED,e);					}						return result;	}
	/**	 *  This method Creates a CookieDomain	 * @param url	 * @param ssoToken	 * @return	 * @throws SAMLConfigurationException	 */
	private static String createCookieDomain(String url, SSOToken ssoToken) throws SAMLConfigurationException{
		String result=null;		Map env = new HashMap();		try {			LOG.info("###### Creation of  Cookie Domain Starts ########");			StringOutputWriter outputWriter = new StringOutputWriter();									String[] arg = {"add-attr-defs","-s","iPlanetAMPlatformService","-t","global","-a","iplanet-am-platform-cookie-domains="+url};
			    outputWriter = new StringOutputWriter();			    			    			    env.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER,outputWriter);
			    env.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");                    
			    env.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			    CommandManager cmd = new CommandManager(env);
			    CLIRequest req = new CLIRequest(null, arg, ssoToken);
				cmd.addToRequestQueue(req);
				cmd.serviceRequestQueue();
				result = outputWriter.getMessages();
				LOG.debug(" CookieDomain Message :" + result);								LOG.info("###### Creation of  Cookie Domain Completed ########");						} catch (Exception e) {			LOG.error("Failed to create a Cookie Domain ", e);			throw new SAMLConfigurationException(SAMLFaultCode.CREATE_COOKIE_DOMAIN_FAILED,e);		}
		return result;
	}
	
	public static String readFile(String fileName) throws Exception{
		
		InputStream iStream = FederationUtil.class.getResourceAsStream(fileName);
        BufferedReader in = new BufferedReader(new InputStreamReader(iStream));
        StringBuffer result = new StringBuffer();
        String inputLine;
        while ((inputLine = in.readLine()) != null){
        	result.append(inputLine);
        }
            
        in.close();
        return result.toString();		
	}	
	public static void main(String[] args) throws Exception{
		FederationUtil.readFile("sp_extended.xml");
	}

}
