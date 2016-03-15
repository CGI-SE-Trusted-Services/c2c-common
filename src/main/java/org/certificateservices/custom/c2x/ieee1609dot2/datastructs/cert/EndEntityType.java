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

/**
 * This type indicates which type of permissions may appear in end-entity certificates the chain of whose permissions passes 
 * through the ItsSspDepthRange field containing this value. If app is indicated, the end- entity certificate may contain an 
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
	public EndEntityType(){
		super(BITSTRING_SIZE);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public EndEntityType(boolean app, boolean enroll) throws IllegalArgumentException{
		super(0,BITSTRING_SIZE,true);
		setFlag(APP, app);
		setFlag(ENROLL, enroll);
	}
	
	
	public boolean isApp(){
		return getFlag(APP);
	}
	
	public boolean isEnroll(){
		return getFlag(ENROLL);
	}

	
	@Override
	public String toString() {
		return "EndEntityType [app=" + isApp()+ ", enroll=" +  isEnroll() + "]";
	}
	
}
