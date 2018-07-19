package com.jamcracker.common.security.authentication;

import java.util.Date;

import javax.security.auth.Subject;

public class AuthTokenImpl implements AuthToken
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -1757792269599921782L;
	private int userID;
	private int companyID;
	private Subject subject = null;
		
	public AuthTokenImpl()
	{
				
	}
	
	public AuthTokenImpl(int userID, int companyID)
	{
		this.userID=userID;
		this.companyID = companyID;
		
	}
	
	public AuthTokenImpl(int userID, int companyID,	Subject subject) {
		this.userID = userID;
		this.companyID = companyID;
		this.subject = subject;
	}
	
	public int getCompanyID()
	{
		return companyID;
	}
	public int getUserID()
	{
		return userID;
	}
	
	
	
	public Subject getSubject() {
		return subject;
	}

	public void setSubject(Subject subject) {
		this.subject = subject;
	}
}