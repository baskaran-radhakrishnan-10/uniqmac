package com.jamcracker.common.security.keymgmt.api;

import org.apache.log4j.Logger;

import com.jamcracker.common.jccache.CacheHandler;

/**
 * @author tmarum
 * 
 */
public class KeyMgmtCache {
	
	private static final String JC_CRYPTO_KEY_CACHE_REGION = "JC_CRYPTO_KEY_CACHE_REGION";
	private static final String JC_CHILD_PARENT_REGION = "JC_CHILD_PARENT_REGION";

	private static final Logger logger = Logger.getLogger(KeyMgmtCache.class);
	public static void put(Object key, Object value) {
		CacheHandler.putValue(JC_CRYPTO_KEY_CACHE_REGION,key, value);
	}
	
	public static Object get(Object key) {
		Object object = null; 
		try {
			object = CacheHandler.getValue(JC_CRYPTO_KEY_CACHE_REGION,key);
		} catch (Exception e) {
			logger.error(e, e);
		}
		return object;
	}
	
	public static void putParent(Object key, Object value) {
		CacheHandler.putValue(JC_CHILD_PARENT_REGION,key, value);
	}
	
	public static Integer getParent(Object key) {
		Object object = null; 
		try {
			object = CacheHandler.getValue(JC_CHILD_PARENT_REGION,key);
		} catch (Exception e) {
			logger.error(e, e);
		}
		return (Integer) object;
	}
}
