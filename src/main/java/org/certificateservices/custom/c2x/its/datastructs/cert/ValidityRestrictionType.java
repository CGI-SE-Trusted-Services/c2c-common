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
package org.certificateservices.custom.c2x.its.datastructs.cert;


/**
 * <code>
 * enum {
 *  time_end(0),
 *  time_start_and_end(1),
 *  time_start_and_duration(2),
 *  region(3),
 *  (2^8-1)
 * } ValidityRestrictionType;
 * </code>
 * <p>
 * This enumeration lists the possible types of restrictions to a certificate's validity.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum ValidityRestrictionType {
	time_end(0),
	time_start_and_end(1),
	time_start_and_duration(2),
	region(3);
	
	private int byteValue;
	
	ValidityRestrictionType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}

	/**
	 * Method returning a Validity Restriction Type by it's byte value.
	 */
	public static ValidityRestrictionType getByValue(int value){
		for(ValidityRestrictionType next : ValidityRestrictionType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}
	
	

}