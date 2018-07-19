/***************************************************

import java.io.BufferedReader;

public class FederationUtil {
	private static final Logger LOG = Logger.getLogger(FederationUtil.class);
	/**

		createRealmAndCot(realm, ssoToken);
		createDataStore(realm, ssoToken);
		createCookieDomain(storeURL, ssoToken);
		createHostedSP(realm, spMetadataTemplate,spExtendedTemplate, certificateName, ssoToken);
		createRemoteIDp(realm, remoteMetaData);
	}


	private static void createDataStore(String realm, SSOToken ssoToken) throws SAMLConfigurationException {
		try {
			StringOutputWriter outputWriter = new StringOutputWriter();
			String arg[] = {
					"update-datastore",
					"--realm",
					"/"+realm,
					"--name",
					"embedded",
					"--attributevalues",
					"sunIdRepoClass=" + idRepoImplClass,
        	CLIRequest req = null;
			Map env = new HashMap();
			env.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");
			env.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			CommandManager cmd = new CommandManager(env);
			req = new CLIRequest(null, arg, ssoToken);
			cmd.addToRequestQueue(req);
			cmd.serviceRequestQueue();
		} catch (CLIException e) {
			LOG.error("Failed to Create Data Store :  " ,e);
		}
	}
   /**
	private static void createRemoteIDp(String realm, String metaData) throws SAMLConfigurationException{
		try {
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
			cof.addCircleOfTrustMember(realm, "cot",COTConstants.SAML2, remoteIDPEntityID);
	}
	/**
	      
			   StringOutputWriter outputWriter = new StringOutputWriter();
					realm,
					"--serviceprovider", "/"+realm+"/sp", // Realm_Demo is the
					};
			Map env = new HashMap();
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
			metaManager.createEntityConfig(realm, extendConfigElm);
			cof.addCircleOfTrustMember(realm, "cot",COTConstants.SAML2, hostedSPEntityID);
		return;
	}
   /**
	private static String createRealmAndCot(String realm, SSOToken ssoToken) throws SAMLConfigurationException{
		String result=null;
			String[] arg1 = { "create-realm", "--realm", realm };
			Map env1 = new HashMap();
			env1.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER, outputWriter);
			env1.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");
			env1.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			req = new CLIRequest(null, arg1, ssoToken);
			cmd.addToRequestQueue(req);
			cmd.serviceRequestQueue();
     		// Cot-Creation under realm
			String arg2[] = { "create-cot", "--cot", "cot", "--realm", realm };
			Map env2 = new HashMap();
			env2.put(CLIConstants.SYS_PROPERTY_OUTPUT_WRITER, outputWriter);
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
			Map env3 = new HashMap();
			env3.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");
			env3.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			cmd = new CommandManager(env3);
			CLIRequest req3 = new CLIRequest(null, arg1, ssoToken);
			cmd.addToRequestQueue(req3);
			cmd.serviceRequestQueue();
	/**
	private static String createCookieDomain(String url, SSOToken ssoToken) throws SAMLConfigurationException{
		String result=null;
			    outputWriter = new StringOutputWriter();
			    env.put(CLIConstants.SYS_PROPERTY_DEFINITION_FILES,"com.sun.identity.cli.AccessManager");                    
			    env.put(CLIConstants.SYS_PROPERTY_COMMAND_NAME, "ssoadm");
			    CommandManager cmd = new CommandManager(env);
			    CLIRequest req = new CLIRequest(null, arg, ssoToken);
				cmd.addToRequestQueue(req);
				cmd.serviceRequestQueue();
				result = outputWriter.getMessages();
				LOG.debug(" CookieDomain Message :" + result);
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