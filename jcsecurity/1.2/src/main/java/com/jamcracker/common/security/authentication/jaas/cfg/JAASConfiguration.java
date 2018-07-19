/*
 * Class: JAASConfiguration
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/jaas/cfg/JAASConfiguration.java>>
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
package com.jamcracker.common.security.authentication.jaas.cfg;

import java.util.Hashtable;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import com.jamcracker.common.security.authentication.jaas.JAASConstants;
import com.jamcracker.common.security.module.JCLoginModule;
import com.jamcracker.common.security.module.JCLoginModule1;

/**
 * The JAAS security provider implementation.
 */
public class JAASConfiguration extends Configuration {

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(JAASConfiguration.class.getName());

	public static final String LOGIN_MODULE = JCLoginModule.class.getName();
	public static final String LOGIN_MODULE_OLD = JCLoginModule1.class.getName();

	protected static Map<String, AppConfigurationEntry[]> appConfigMap = new Hashtable<String, AppConfigurationEntry[]>();

	protected Configuration prevConfiguration = null;

	public JAASConfiguration(Configuration prevConfiguration) {
		this.prevConfiguration = prevConfiguration;
	}

	static {
		loadAppConfig();
	}

	public static void loadAppConfig() {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start loadAppConfig() Method of JAASConfiguration ");
		}

		Map<String, Object> options = new Hashtable<String, Object>();

		AppConfigurationEntry[] appCfgEntries = new AppConfigurationEntry[] { new AppConfigurationEntry(
				LOGIN_MODULE,
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
		AppConfigurationEntry[] appCfgEntries1 = new AppConfigurationEntry[] { new AppConfigurationEntry(
				LOGIN_MODULE_OLD,
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };

		appConfigMap.put(JAASConstants.LOGIN_MODULE_NAME, appCfgEntries);
		appConfigMap.put(JAASConstants.LOGIN_MODULE_NAME_OLD, appCfgEntries1);

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end loadAppConfig() Method of JAASConfiguration ");
		}
	}

	@Override
	public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER
					.debug("JAASConfiguration : getAppConfigurationEntry : searching for application = "
							+ appName);
		}
		if (appConfigMap.containsKey(appName)) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("JAASConfiguration : found application = "
						+ appName);
			}
			return appConfigMap.get(appName);
		}

		return this.prevConfiguration.getAppConfigurationEntry(appName);
	}
}
