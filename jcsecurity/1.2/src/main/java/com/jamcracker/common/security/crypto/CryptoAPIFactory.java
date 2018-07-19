package com.jamcracker.common.security.crypto;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.keymgmt.api.KeyManager;

public class CryptoAPIFactory  {
	
	/**
	 * This has to be injected through spring.
	 */
	private static ApplicationContext context;
	
	private static CryptoAPIFactory _instance;
	
	
	private static final String CONTEXT_XML = "jccrypto-context.xml";
	
	private ICryptoAPI cryptoAPI;
	private KeyManager keyManager;

	static {
		context = new ClassPathXmlApplicationContext( new String[] {CONTEXT_XML});
		}
	
	private CryptoAPIFactory () {
		cryptoAPI = (ICryptoAPI)context.getBean(JCSecurityConstants.JC_CRYPTOAPI);
		keyManager = (KeyManager) context.getBean(JCSecurityConstants.JC_KEY_MGR);
	}
	
	public static CryptoAPIFactory getInstance() {
		if (_instance == null) {
			_instance = new CryptoAPIFactory();
		}
		return _instance;
	}
	
	public ICryptoAPI getCryptoAPI() {
		
		return this.cryptoAPI;
	}

	public KeyManager getKeyManager() {
		return keyManager;
	}
	
}
