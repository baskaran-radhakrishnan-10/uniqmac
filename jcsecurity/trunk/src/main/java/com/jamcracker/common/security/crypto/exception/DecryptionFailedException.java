package com.jamcracker.common.security.crypto.exception;

import com.jamcracker.common.exception.JCFaultCode;

/**
 * Exception to handle encrypt cryptograohic operation failures
 * @author marumugam
 *
 */
@SuppressWarnings("serial")
public class DecryptionFailedException extends JCCryptoException {
	public DecryptionFailedException(final JCFaultCode code, final Throwable exception) {
		super(code, exception);
	}
	public DecryptionFailedException(final JCFaultCode errorCode) {
		super(errorCode);
	}
}
