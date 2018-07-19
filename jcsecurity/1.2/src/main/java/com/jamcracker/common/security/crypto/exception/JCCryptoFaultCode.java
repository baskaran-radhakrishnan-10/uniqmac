package com.jamcracker.common.security.crypto.exception;

import com.jamcracker.common.exception.JCFaultCode;
import com.jamcracker.common.security.crypto.core.JCCryptoConstants;

public class JCCryptoFaultCode extends JCFaultCode {

	private static final long serialVersionUID = -2183237064474898565L;
	
	protected static final String SUB_MODULE_CRYPT = "CR";

	protected JCCryptoFaultCode(String faultCode) {

		super(faultCode);

	}
	
	protected JCCryptoFaultCode(String errorType, String subModule, String errorCode){
		super(
				new StringBuilder(errorType).append("CO").append(subModule).append(errorCode).toString()
		);
	}
	
	public static final JCCryptoFaultCode CRYPTO_INTERNAL_ERROR = new JCCryptoFaultCode(JCCryptoConstants.INTERNAL_ERROR_FAULT_CODE, SUB_MODULE_CRYPT, "0001");
}
