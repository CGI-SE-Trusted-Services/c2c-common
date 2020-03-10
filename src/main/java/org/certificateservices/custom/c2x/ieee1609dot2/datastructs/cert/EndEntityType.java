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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert;

import org.certificateservices.custom.c2x.asn1.coer.COERBitString;

import java.io.IOException;

/**
 * This type indicates which type of permissions may appear in end-entity certificates the chain of whose permissions passes 
 * through the PsidGroupPermissions field containing this value. If app is indicated, the end- entity certificate may contain an
 * appPermissions field. If enroll is indicated, the end-entity certificate may contain an certRequestPermissions field.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EndEntityType extends COERBitString {
	
	private static final long serialVersionUID = 1L;
	
	private static final int BITSTRING_SIZE=8;
	
	private static final int APP = 0;
	private static final int ENROLL = 1;

	/**
	 * Constructor used when decoding
	 */
	public EndEntityType() throws IOException{
		super(BITSTRING_SIZE);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public EndEntityType(boolean app, boolean enroll) throws IOException{
		super(0,BITSTRING_SIZE,true);
		if(!app && !enroll){
			throw new IOException("Invalid EndEntityType, either app or enroll flag must be set.");
		}
		setFlag(APP, app);
		setFlag(ENROLL, enroll);
	}
	
	
	public boolean isApp() {
		try {
			return getFlag(APP);
		}catch(IOException e){
			throw new RuntimeException("Error parsing EndEntityType, flag APP: " + e.getMessage(),e);
		}
	}

	public boolean isEnroll() {
		try {
			return getFlag(ENROLL);
		} catch (IOException e) {
			throw new RuntimeException("Error parsing EndEntityType, flag ENROLL: " + e.getMessage(), e);
		}
	}

	
	@Override
	public String toString() {
		return "EndEntityType [app=" + isApp()+ ", enroll=" +  isEnroll() + "]";
	}
	
}
