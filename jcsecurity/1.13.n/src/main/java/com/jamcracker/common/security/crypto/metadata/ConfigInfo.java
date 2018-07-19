package com.jamcracker.common.security.crypto.metadata;

import java.io.Serializable;

/**
 * A class used for ConfigInfo CMX data Name Id mapping configuration For
 * example Alg name[AES,CAST,BLOWFISH] has dedicated id mapping in jcp_config
 * table with values starting from 2000,2001,2002,same will be used for
 * Prepending CMX data in encrypted value
 * 
 * @author marumugam
 * 
 */

public class ConfigInfo implements Serializable {

	private static final long serialVersionUID = 6458707885712406616L;

	private String configId;
	private String actorId;
	private String configKey;
	private String configValue;

	/**
	 * @return configId
	 */

	public String getConfigId() {
		return configId;
	}

	/**
	 * @param configId
	 */
	public void setConfigId(String configId) {
		this.configId = configId;
	}

	/**
	 * @return actorId
	 */
	public String getActorId() {
		return actorId;
	}

	/**
	 * @param actorId
	 */
	public void setActorId(String actorId) {
		this.actorId = actorId;
	}

	/**
	 * @return configKey
	 */
	public String getConfigKey() {
		return configKey;
	}

	/**
	 * @param configKey
	 */
	public void setConfigKey(String configKey) {
		this.configKey = configKey;
	}

	/**
	 * @return configValue
	 */
	public String getConfigValue() {
		return configValue;
	}

	/**
	 * @param configValue
	 */
	public void setConfigValue(String configValue) {
		this.configValue = configValue;
	}

	@Override
	public String toString() {
		return configKey + "=" + configValue;
	}

}