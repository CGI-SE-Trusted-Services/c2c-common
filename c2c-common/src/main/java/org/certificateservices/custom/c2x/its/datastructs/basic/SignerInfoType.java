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
package org.certificateservices.custom.c2x.its.datastructs.basic;


/**
 * <code>
 * enum {
 *   self(0),
 *   certificate_digest_with_ecdsap256(1),
 *   certificate(2),
 *   certificate_chain(3),
 *   certificate_digest_with_other_algorithm(4),
 *   reserved(240..255),
 *   (2^8-1)
 * } SignerInfoType;
 * </code>
 * <p>
 *
 * This enumeration lists methods to describe a message's signer. Values in the range of 240 to 255 shall not be used as
 * they are reserved for internal testing purposes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum SignerInfoType {
	self(0),
	certificate_digest_with_ecdsap256( 1),
	certificate( 2),
	certificate_chain( 3),
	certificate_digest_with_other_algorithm( 4);
	
	private int byteValue;
	
	SignerInfoType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a Signer Infot by it's byte value.
	 */
	public static SignerInfoType getByValue(int value){
		for(SignerInfoType next : SignerInfoType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}