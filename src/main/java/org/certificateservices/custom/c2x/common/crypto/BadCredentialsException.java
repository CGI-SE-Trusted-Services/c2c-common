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
 * Exception thrown if supplied credentials to authenticate towards underlying hardward cryptographic was wrong.
 *  
 * @author Philip
 *
 */
public class BadCredentialsException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown if supplied credentials to authenticate towards underlying hardward cryptographic was wrong.
	 */
	public BadCredentialsException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Exception thrown if supplied credentials to authenticate towards underlying hardward cryptographic was wrong.
	 */
	public BadCredentialsException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	
	
}
