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
 *   verification_key(0),
 *   encryption_key(1),
 *   assurance_level(2),
 *   reconstruction_value(3),
 *   its_aid_list(32),
 *   its_aid_ssp_list(33),
 *   priority_its_aid_list(34), // Only for version 1
 *   priority_ssp_list(35), // Only for version 1
 * } SubjectAttributeType;
 * </code>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum SubjectAttributeType {
	verification_key( 0),
	encryption_key( 1),
	assurance_level( 2),
	reconstruction_value( 3),
	its_aid_list( 32),
	its_aid_ssp_list( 33),
	priority_its_aid_list( 34), // Only for version 1
	priority_ssp_list( 35); // Only for version 1
	
	
	private int byteValue;
	
	SubjectAttributeType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a Subject Attribute Type by it's byte value.
	 */
	public static SubjectAttributeType getByValue(int value){
		for(SubjectAttributeType next : SubjectAttributeType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}

