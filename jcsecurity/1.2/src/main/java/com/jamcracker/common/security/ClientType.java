/*
 * Class: ClientType
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/ClientType.java>>
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
package com.jamcracker.common.security;

/**
 * The client accessing the security framework.
 */
public class ClientType implements java.io.Serializable {

	private static final long serialVersionUID = 2482253392205127984L;
	/**
	 * Depending on the client type the authentication framework may require
	 * additional information.
	 */
	public static final ClientType UNKNOWN = new ClientType("UNKNOWN");
	public static final ClientType UI = new ClientType("UI");
	public static final ClientType WEB_SERVICE = new ClientType("WEB_SERVICE");
	public static final ClientType CLIENT_SIDE_APP = new ClientType(
			"CLIENT_SIDE_APP");

	private static ClientType[] clientTypes = { UI, WEB_SERVICE,
			CLIENT_SIDE_APP };

	private String clientType = null;

	private ClientType(String clientType) {
		this.clientType = clientType;
	}

	public static ClientType parseClientType(String clientType) {

		for (int i = 0; i < clientTypes.length; i++) {

			if (clientTypes[i].clientType.equals(clientType)) {
				return clientTypes[i];
			}
		}

		return UNKNOWN;
	}

	public boolean equals(Object other) {

		if ((other instanceof ClientType)) {
			return ((ClientType) other).clientType.equals(this.clientType);
		}

		return false;
	}

	public String toString() {
		return this.clientType;
	}

}
