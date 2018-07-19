/*
 * Class: JCAuthenticationToken
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Initial version
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
package com.jamcracker.common.security.authentication;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

import javax.security.auth.Subject;

import com.jamcracker.common.security.authentication.jaas.JAASAuthenticationPrivateToken;
import com.jamcracker.common.security.spec.IAuthenticationPrivateToken;
import com.jamcracker.common.security.spec.IUserWebSession;
import com.jamcracker.security.authentication.PasswordGenerator;
import com.jamcracker.security.identity.Identity;

/**
 * The authentication token representing user.
 */
public class JCAuthenticationToken implements IJCAuthenticationToken {
	private static final long serialVersionUID = -3184930523264879337L;
	public static final JCAuthenticationToken INVALID_JCAUTH_TOKEN = new JCAuthenticationToken();
	private int userID;
	private int companyID;
	private String userName;
	private String companyAcronym;
	private Date authnInstant;
	private String sessionID;
	private String clientType = null;
	protected IAuthenticationPrivateToken authPrivateToken = null;
	protected AuthenticationInfo authInfo = null;

	public JCAuthenticationToken() {
	}

	public JCAuthenticationToken(int userID, int companyID, String userName,
			String companyAcronym) {
		this.userID = userID;
		this.companyID = companyID;
		this.userName = userName;
		this.companyAcronym = companyAcronym;
		this.authnInstant = new Date();
		this.sessionID = createSessionID(this.userID);
	}

	public JCAuthenticationToken(AuthenticationInfo authInfo,
			IAuthenticationPrivateToken authPrivateToken) {
		this.authInfo = authInfo;
		setAuthPrivateToken(authPrivateToken);
		JAASAuthenticationPrivateToken privToken = 
			(JAASAuthenticationPrivateToken) authPrivateToken;
		
		Map userContextMap = privToken.getUserContextMap();
		if(userContextMap != null && !userContextMap.isEmpty()){
			Identity identity = (Identity)userContextMap.get(IUserWebSession.PIVOT_PATH_IDENTITY);
			companyID = identity.getCompanyID();
			userID = identity.getUserID();
			userName = identity.getLoginName();
			companyAcronym = identity.getCompanyAcronym();
			authnInstant = new Date();
			sessionID = identity.getAuthenticationToken().getSessionID();
			
		}
		
		
	}

	private String createSessionID(int userID) {
		/* this create a new session id and will be used as key in the hashmap in
		 authentication which is the controller of the auth tokens..
		 this should contain the timeinstant as well.
		Session ID to be created in the following format
		userid:<8 digit random>:yyyymmddssmmm" ,For random use PasswordGenerator class.
		*/
		String mid = new PasswordGenerator().generatePassword(8);
		String sessionId = userID + ":" + mid + ":" + getTimeInstant();
		return sessionId;
	}
	/*
	 * Method creates a time stamp of the format yyyymmddhhssmmm
	 * representing the current time
	 */
	private String getTimeInstant() {
		GregorianCalendar gCal = new GregorianCalendar();
		String authInstant = "" + gCal.get(Calendar.YEAR)
				+ (gCal.get(Calendar.MONTH) + 1) + gCal.get(Calendar.DATE)
				+ gCal.get(Calendar.HOUR) + gCal.get(Calendar.MINUTE)
				+ gCal.get(Calendar.SECOND) + gCal.get(Calendar.MILLISECOND);
		return authInstant;
	}

	public String getSessionID() {
		return sessionID;
	}

	public int getCompanyID() {
		return companyID;
	}

	public int getUserID() {
		return userID;
	}

	public String getUserName() {
		return userName;
	}

	public String getCompanyAcronym() {
		return companyAcronym;
	}

	public Date getAuthenticationInstant() {
		return authnInstant;
	}

	public java.lang.String getClientType() {
		return clientType;
	}

	public void setClientType(java.lang.String clientType) {
		this.clientType = clientType;
	}

	private String localToString() {
		StringBuffer text = new StringBuffer();
		text.append("; userID=");
		text.append(userID);
		text.append("; companyID=");
		text.append(companyID);
		text.append("; authnInstant=");
		text.append(authnInstant.toString());

		return text.toString();
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.authentication.IJCAuthenticationToken#getAuthPrivateToken()
 */
	public IAuthenticationPrivateToken getAuthPrivateToken() {
		return authPrivateToken;
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.authentication.IJCAuthenticationToken#setAuthPrivateToken(com.jamcracker.common.security.spec.IAuthenticationPrivateToken)
 */
	public void setAuthPrivateToken(
			IAuthenticationPrivateToken authPrivateToken) {

		if (authPrivateToken != null) {
			this.authPrivateToken = authPrivateToken;
			this.authPrivateToken.setAuthenticationToken(this);
		}
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.authentication.IJCAuthenticationToken#isValid()
 */
	public boolean isValid() {
		return (authPrivateToken != null);
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.authentication.IJCAuthenticationToken#getAuthInfo()
 */
	public AuthenticationInfo getAuthInfo() {
		return authInfo;
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.authentication.IJCAuthenticationToken#setAuthInfo(com.jamcracker.common.security.authentication.AuthenticationInfo)
 */
	public void setAuthInfo(AuthenticationInfo authInfo) {
		this.authInfo = authInfo;
	}
/*
 * 	(non-Javadoc)
 * @see com.jamcracker.common.security.authentication.IJCAuthenticationToken#hasLoggedIn()
 */
	public boolean hasLoggedIn() {
		return isValid() && getAuthPrivateToken().hasLoggedIn();
	}
/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.authentication.IJCAuthenticationToken#logout()
	 */
	public void logout() {
		
		if (hasLoggedIn()) {
			getAuthPrivateToken().logout();
		}
	}
	public String toString() {

		if (authInfo != null) {
			return "JCAuthenticationToken" + authInfo.getPrintableString();
		}

		return super.toString();
	}

	@Override
	public Subject getSubject() {
		// TODO Auto-generated method stub
		return null;
	}
}
