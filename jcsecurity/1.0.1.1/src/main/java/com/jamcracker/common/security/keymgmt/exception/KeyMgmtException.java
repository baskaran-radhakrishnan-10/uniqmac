/**
 * 
 */
package com.jamcracker.common.security.keymgmt.exception;

import com.jamcracker.common.exception.BaseException;
import com.jamcracker.common.exception.JCFaultCode;

/**
 * @author tmarum
 *
 */
public class KeyMgmtException extends BaseException {

	public KeyMgmtException(final JCFaultCode code, final Throwable exception) {
		super(code, exception);
	}
	public KeyMgmtException(final JCFaultCode errorCode) {
		super(errorCode);
	}

}
