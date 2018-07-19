package com.jamcracker.common.security.crypto.exception;

import com.jamcracker.common.exception.JCFaultCode;

/**
 * Exception to handle encrypt cryptograohic operation failures
 * @author marumugam
 *
 */
@SuppressWarnings("serial")
public class EncryptionFailedException extends JCCryptoException {
	public EncryptionFailedException(final JCFaultCode code, final Throwable exception) {
		super(code, exception);
	}
	public EncryptionFailedException(final JCFaultCode errorCode) {
		super(errorCode);
	}
}
