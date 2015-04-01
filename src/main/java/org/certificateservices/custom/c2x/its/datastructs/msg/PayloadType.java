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
package org.certificateservices.custom.c2x.its.datastructs.msg;


/**
 * <code>
 * enum {
 *   unsecured(0),
 *   signed(1),
 *   encrypted(2),
 *   signed_external(3),
 *   signed_and_encrypted(4),
 *   (2^8-1)
 *   } PayloadType;
 * </code>
 * <p>
 * This enumeration lists the supported types of payloads.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum PayloadType {
	unsecured( 0),
	signed(1),
	encrypted(2),
	signed_external(3),
	signed_and_encrypted(4);
	
	private int byteValue;
	
	PayloadType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a header field by it's byte value.
	 */
	public static PayloadType getByValue(int value){
		for(PayloadType next : PayloadType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}