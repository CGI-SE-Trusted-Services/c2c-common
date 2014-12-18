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
 *  enrollment_credential(0),
 *  authorization_ticket(1),
 *  authorization_authority(2),
 *  enrollment_authority(3),
 *  root_ca(4),
 *  crl_signer(5),
 * (2^8-1)
 * } SubjectType;
 * </code>
 * <p>
 * This enumeration lists the possible types of subjects:
 * <li> Regular ITS stations shall use certificates containing a SubjectInfo of SubjectType
 * enrollment_credential when communicating with Enrollment CAs. Such certificates shall not be
 * accepted as signers of other certificates or in regular communication by other ITS-Stations.
 * <li> Regular ITS stations shall use certificates containing a SubjectInfo of SubjectType
 * authorization_ticket when communicating with other ITS-Stations. Such certificates shall not be 
 * accepted as signers of other certificates.
 * <li> Authorization CAs, which sign authorization tickets (pseudonyms) for ITS stations, shall use the 
 * SubjectType authorization_authority.
 * <li> Enrollment CAs, which sign enrollment credentials (long term certificates) for ITS stations, shall use the
 * SubjectType enrollment_authority.
 * <li>Root CAs, which sign certificates of other CAs, shall use the SubjectType root_ca.
 * <li>Certificate revocation list signers shall use SubjectType crl_signer.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum SubjectType {
	enrollment_credential(0),
	authorization_ticket(1),
	authorization_authority( 2),
	enrollment_authority(3),
	root_ca(4),
	crl_signer(5);
	
	private int byteValue;
	
	SubjectType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a Subject Type by it's byte value.
	 */
	public static SubjectType getByValue(int value){
		for(SubjectType next : SubjectType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}
