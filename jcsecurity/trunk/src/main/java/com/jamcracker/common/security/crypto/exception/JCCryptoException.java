package com.jamcracker.common.security.crypto.exception;

import com.jamcracker.common.exception.BaseException;
import com.jamcracker.common.exception.JCFaultCode;

/**
 * Exception to handle cryptograohic operation failures
 * @author kkpushparaj
 *
 */
@SuppressWarnings("serial")
public class JCCryptoException extends BaseException {
	public JCCryptoException(final JCFaultCode code, final Throwable exception) {
		super(code, exception);
	}
	public JCCryptoException(final JCFaultCode errorCode) {
		super(errorCode);
	}
}
