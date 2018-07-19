package com.jamcracker.common.security.crypto;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import com.jamcracker.common.security.keymgmt.service.KeyManagementService;

public final class CryptoServiceFactory implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	private static CryptoServiceFactory instance;

	private static final String BEAN_ID_KEY_MANAGEMENT = "keyManagement";
	public static final String BEAN_ID_JC_CRYPTOAPI = "cryptoServiceAPI";
	

	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}
	
	private CryptoServiceFactory(){
		
	}

	public static CryptoServiceFactory getInstance() {
		if (instance == null) {
			instance = new CryptoServiceFactory();
		}
		return instance;
	}

	public CryptoService getCryptoService() {
		CryptoService cryptoAPI = (CryptoService) applicationContext.getBean(BEAN_ID_JC_CRYPTOAPI);
		return cryptoAPI;
	}

	public KeyManagementService getKeyManagementService() {
		KeyManagementService keyManager = (KeyManagementService) applicationContext.getBean(BEAN_ID_KEY_MANAGEMENT);
		return keyManager;
	}

}
