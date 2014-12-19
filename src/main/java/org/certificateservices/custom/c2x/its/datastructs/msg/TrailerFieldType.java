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
 *  signature(1),
 *  (2^8-1)
 * } TrailerFieldType;
 * </code>
 * <p>
 * This enumeration lists the supported types of trailer fields.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum TrailerFieldType {
	signature( 1);
	
	private int byteValue;
	
	TrailerFieldType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a trailer field by it's byte value.
	 */
	public static TrailerFieldType getByValue(int value){
		for(TrailerFieldType next : TrailerFieldType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}