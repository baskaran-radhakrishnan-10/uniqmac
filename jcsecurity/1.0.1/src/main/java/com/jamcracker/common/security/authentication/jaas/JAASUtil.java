/*
 * Class: JAASUtil
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/jaas/JAASUtil.java>>
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 ******************************************************/
package com.jamcracker.common.security.authentication.jaas;

import java.security.AccessControlException;
import java.security.Permission;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;

/**
 * This utility is useful to check whether the user is having access to a
 * particular permission.
 */
public abstract class JAASUtil {

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(JAASUtil.class.getName());

	public static boolean isAccessPermitted(Subject subj,
			final Permission permission) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start isAccessPermitted() Method of JAASUtil");
		}
		if (permission == null) {
			return false;
		}
		if (subj == null) {
			subj = new Subject();
		}

		final SecurityManager curSecurityManager;

		if (System.getSecurityManager() == null) {
			curSecurityManager = new SecurityManager();
		} else {
			curSecurityManager = System.getSecurityManager();
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Trying to authorize subject : " + subj
					+ ", with permission : " + permission);
		}
		boolean permissionGranted = false;

		try {
			Subject.doAsPrivileged(subj, new PrivilegedExceptionAction() {

				public Object run() {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Current Security Manager : "
								+ curSecurityManager);
					}
					curSecurityManager.checkPermission(permission);
					return null;
				}

			}, null);

			permissionGranted = true;

		} catch (AccessControlException ace) {
			LOGGER.error("AccessControlException occured : " , ace);
			permissionGranted = false;
		} catch (PrivilegedActionException pae) {
			LOGGER.error("PrivilegedActionException occured : " , pae);
			permissionGranted = false;
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("In isAccessPermitted returning permissionGranted = "
					+ permissionGranted);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end isAccessPermitted() Method of JAASUtil");
		}
		return permissionGranted;
	}
}
