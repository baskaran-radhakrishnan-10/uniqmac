package com.jamcracker.commons.core.dataobject;

import java.io.Serializable;

public class UserCLRDTO implements Serializable{
	private String jSessionId;
	
	private long creationTime;
	
	private String ipAddress;
	
	private String browserInformation;

	public String getjSessionId() {
		return jSessionId;
	}

	public void setjSessionId(String jSessionId) {
		this.jSessionId = jSessionId;
	}

	public long getCreationTime() {
		return creationTime;
	}

	public void setCreationTime(long creationTime) {
		this.creationTime = creationTime;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getBrowserInformation() {
		return browserInformation;
	}

	public void setBrowserInformation(String browserInformation) {
		this.browserInformation = browserInformation;
	}

}
