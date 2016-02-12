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
 * Exception thrown by CryptoManager if a signature cannot be verified.
 * 
 * @author Philip Vendil
 *
 */
public class InvalidSignatureException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown by CryptoManager if a signature cannot be verified.
	 * 
	 * @param message
	 * @param cause
	 */
	public InvalidSignatureException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown by CryptoManager if a signature cannot be verified.
	 * 
	 * @param message
	 */
	public InvalidSignatureException(String message) {
		super(message);
	}

}
