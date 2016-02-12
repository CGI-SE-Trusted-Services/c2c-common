/************************************************************************
*                                                                       *
*  Certificate Service -  Car2Car Core                                  *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.custom.c2x.common.crypto;


/**
 * Configuration parameters for the DefaultCryptoManager, containing the provider to be used for underlying cryptographic operations.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class DefaultCryptoManagerParams implements CryptoManagerParams {
	
	private String provider;
		
	/**
	 * Configuration parameters for the DefaultCryptoManager, containing the provider to be used for underlying cryptographic operations.
	 * @param provider the provider to use.
	 */
	public DefaultCryptoManagerParams(String provider) {
		super();
		this.provider = provider;
	}

	/**
	 * 
	 * @return containing the provider to be used for underlying cryptographic operations.
	 */
	public String getProvider() {
		return provider;
	}
	
	

}
