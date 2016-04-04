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
 *   generation_time(0),
 *   generation_time_confidence(1),
 *   expiration(2),
 *   generation_location(3),
 *   request_unrecognized_certificate(4),
 *   message_type(5),
 *   signer_info(128),
 *   recipient_info(129),
 *   encryption_parameters(130),
 *   (2^8-1)
 * } HeaderFieldType;
 * </code>
 * <p>
 * This enumeration lists the supported types of header fields.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum HeaderFieldType {

	generation_time( 0, 0),
	generation_time_confidence(1,1),
	expiration(2,2),
	generation_location(3,3),
	request_unrecognized_certificate(4,4),
	message_type(5,-1),
	its_aid(-1,5),
	signer_info(128,128),
	recipient_info(129,130),
	encryption_parameters(130,129);
	
	public static int INVALID_BYTE_VALUE = -1;
	
	private int ver1Value;
	private int ver2Value;
	
	HeaderFieldType(int ver1Value, int ver2Value){
		this.ver1Value = ver1Value;
		this.ver2Value = ver2Value;
	}
	
	public int getByteValue(int protocolVersion){
		if(protocolVersion == 1){
			return ver1Value;
		}
		return ver2Value;
	}
	
	/**
	 * Returns the order the field should be returned when generating secured message. (SignedInfo always first).
	 */
	public int getOrder(int protocolVersion){
		if(this == signer_info){
			return Integer.MIN_VALUE;
		}
		return getByteValue(protocolVersion);
	}
	
	/**
	 * Method returning a header field by it's byte value.
	 */
	public static HeaderFieldType getByValue(int protocolVersion, int value){
		for(HeaderFieldType next : HeaderFieldType.values()){
			if(protocolVersion == 1){
				if(next.ver1Value == value){
					return next;
				}
			}else{
				if(next.ver2Value == value){
					return next;
				}
			}
		}
		return null;
	}

}