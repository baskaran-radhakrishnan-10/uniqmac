/*
 * Class: AbstractSecurityProvider
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/impl/AbstractSecurityProvider.java>>
 * 3.0  05/03/2010   Nisha 				1.0			Added for menu rendering
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
package com.jamcracker.common.security.impl;

import com.jamcracker.common.security.ISessionHandler;
import com.jamcracker.common.security.authentication.AuthToken;
import com.jamcracker.common.security.authorization.ResourceConfig;
import com.jamcracker.common.security.authorization.ResourceType;
import com.jamcracker.common.security.spec.ISecurityProvider;

/**
 * The abstract implementation which provides convenient methods for accessing
 * different types of resources.
 */
public abstract class AbstractSecurityProvider implements ISecurityProvider {

	private static final long serialVersionUID = 3034104912343660147L;

	/**
	 * This method determines whether the user is having access to the specified
	 * URL resource.
	 * 
	 * @param authToken
	 * @param resourceCfg
	 * @return
	 */
	public abstract boolean canAccessURL(AuthToken authToken,
			ResourceConfig resourceCfg);

	/**
	 * This method determines whether the user is having access to specified
	 * event resource.
	 * 
	 * @param authToken
	 * @param resourceCfg
	 * @return
	 */
	public abstract boolean canAccessEvent(AuthToken authToken,
			ResourceConfig resourceCfg);
	/**
	 * This method determines whether the user is having access to widget resource.
	 * 
	 * @param authToken
	 * @param resourceCfg
	 * @return
	 */
	public abstract boolean canAccessWidget(AuthToken authToken,
			ResourceConfig resourceCfg);


	/**
	 * This method determines whether the user is having access to specified JSP
	 * field resource.
	 * 
	 * @param authToken
	 * @param resourceCfg
	 * @return
	 */
	public abstract boolean canAccessField(AuthToken authToken,
			ResourceConfig resourceCfg);
	
	/**
	 * This method determines whether the user is having access to specified Menu
	 * field resource.
	 * 
	 * @param authToken
	 * @param resourceCfg
	 * @return
	 */
	
	public abstract boolean canAccessMenu(AuthToken authToken,
			ResourceConfig resourceCfg);


	/**
	 * Useful deligator method to access specific resource type.
	 */
	@Override
	public boolean canAccessResource(AuthToken authToken,
			ResourceConfig resourceCfg) {

		if (resourceCfg.getResourceType().equals(ResourceType.URL_RESOURCE)) {

			return canAccessURL(authToken, resourceCfg);

		} else if (resourceCfg.getResourceType().equals(
				ResourceType.EVENT_RESOURCE)) {

			return canAccessEvent(authToken, resourceCfg);

		} else if (resourceCfg.getResourceType().equals(
				ResourceType.FIELD_RESOURCE)) {

			return canAccessField(authToken, resourceCfg);
		}else if (resourceCfg.getResourceType().equals(
				ResourceType.MENU_RESOURCE)) {

			return canAccessMenu(authToken, resourceCfg);
		}
		else if (resourceCfg.getResourceType().equals(
				ResourceType.WIDGET_RESOURCE)) {

			return canAccessWidget(authToken, resourceCfg);
		}

		return false;
	}

	public abstract ISessionHandler getSessionHandler() ;

	public abstract  void setSessionHandler(ISessionHandler sessionHandler) ;

}
