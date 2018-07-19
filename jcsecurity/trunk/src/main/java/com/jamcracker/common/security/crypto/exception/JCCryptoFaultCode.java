/*
 * 
 * Class: JCCryptoFaultCode.java
 *
 *
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 *****************************************************
 */
package com.jamcracker.common.security.crypto.exception;

import com.jamcracker.common.exception.JCFaultCode;

public class JCCryptoFaultCode extends JCFaultCode {

	private static final long serialVersionUID = -2183237064474898565L;
		protected static final String INTERNAL_ERROR_FAULT_CODE = "11";	
	protected static final String SUB_MODULE_CRYPT = "CR";

	protected JCCryptoFaultCode(String faultCode) {

		super(faultCode);

	}
	
	protected JCCryptoFaultCode(String errorType, String subModule, String errorCode){
		super(
				new StringBuilder(errorType).append("CO").append(subModule).append(errorCode).toString()
		);
	}
	
	public static final JCCryptoFaultCode CRYPTO_INTERNAL_ERROR = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0001");		public static final JCCryptoFaultCode CRYPTO_NOSUCH_ALGORITHM = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0002");		public static final JCCryptoFaultCode CRYPTO_NOSUCH_PADDIING = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0003");		public static final JCCryptoFaultCode CRYPTO_NOSUCH_PROVIDER = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0004");		public static final JCCryptoFaultCode CRYPTO_INVALID_KEY = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0005");		public static final JCCryptoFaultCode CRYPTO_INVALID_ALG_PARAM = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0006");		public static final JCCryptoFaultCode CRYPTO_ILLEGAL_STATE = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0007");		public static final JCCryptoFaultCode CRYPTO_ILLEGAL_BLOCK_SIZE = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0008");		public static final JCCryptoFaultCode CRYPTO_BAD_PADDING = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0009");		public static final JCCryptoFaultCode CRYPTO_KEY_EXPIRED = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0010");		public static final JCCryptoFaultCode CRYPTO_ENC_FAILURE = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0011");		public static final JCCryptoFaultCode CRYPTO_DEC_FAILURE = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0012");		public static final JCCryptoFaultCode CRYPTO_NO_ACTIVE_KEYS = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0013");
	
	public static final JCCryptoFaultCode CRYPTO_KMF_UNAUTHCACHE_ACCESS = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0014");
	
	public static final JCCryptoFaultCode CRYPTO_KMF_AUTHCACHE_CONFIG_FAILURE = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0015");
	
	public static final JCCryptoFaultCode CRYPTO_KMF_PASSPHRASE_PROP_CONFIG_FAILURE = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0016");
	public static final JCCryptoFaultCode CRYPTO_UNSUPPORTED_ENCODING = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0017");
	
	public static final JCCryptoFaultCode CRYPTO_SIGNATURE_EXCEPTION = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0018");
	
	public static final JCCryptoFaultCode CRYPTO_KETSTORE_EXCEPTION = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0019");
	
	public static final JCCryptoFaultCode CRYPTO_CERTIFICATE_EXCEPTION = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0020");
	
	public static final JCCryptoFaultCode CRYPTO_UNRECORABLE_ENTRY_EXCEPTION = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0021");
	
	public static final JCCryptoFaultCode CRYPTO_NO_ACTIVE_CMXXML = new JCCryptoFaultCode(INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0022");	
}
