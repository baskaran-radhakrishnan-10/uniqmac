package com.jamcracker.common.security.keymgmt.api;

import org.apache.log4j.Logger;

import com.jamcracker.common.jccache.CacheFactory;
import com.jamcracker.common.jccache.CacheService;

/**
 * @author tmarum
 * 
 */
public class KeyMgmtCache {
	private static CacheService cacheService = CacheFactory.getCacheService();
	private static final String JC_CRYPTO_KEY_CACHE_REGION = "JC_CRYPTO_KEY_CACHE_REGION";
	private static final String JC_CHILD_PARENT_REGION = "JC_CHILD_PARENT_REGION";

	private static final Logger logger = Logger.getLogger(KeyMgmtCache.class);
	public static void put(Object key, Object value) {
		cacheService.putValue(JC_CRYPTO_KEY_CACHE_REGION,key, value);
	}
	
	public static Object get(Object key) {
		Object object = null; 
		try {
			object = cacheService.getValue(JC_CRYPTO_KEY_CACHE_REGION,key);
		} catch (Exception e) {
			logger.error(e, e);
		}
		return object;
	}
	
	public static void putParent(Object key, Object value) {
		cacheService.putValue(JC_CHILD_PARENT_REGION,key, value);
	}
	
	public static Integer getParent(Object key) {
		Object object = null; 
		try {
			object = cacheService.getValue(JC_CHILD_PARENT_REGION,key);
		} catch (Exception e) {
			logger.error(e, e);
		}
		return (Integer) object;
	}
}
