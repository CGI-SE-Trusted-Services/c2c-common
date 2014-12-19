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
	generation_time( 0),
	generation_time_confidence(1),
	expiration(2),
	generation_location(3),
	request_unrecognized_certificate(4),
	message_type(5),
	signer_info(128),
	recipient_info(129),
	encryption_parameters(130);
	
	private int byteValue;
	
	HeaderFieldType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a header field by it's byte value.
	 */
	public static HeaderFieldType getByValue(int value){
		for(HeaderFieldType next : HeaderFieldType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}