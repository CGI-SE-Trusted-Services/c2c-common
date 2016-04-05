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
 * Enumeration defining available security profiles used with Secured Messages.
 * <p>
 * This enumeration is only used for version 1 of the Secured Message Protocol.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum MessageType {
	CAM(2,1),
	DENM(1,2);
	
	private int value;
	private int securityProfile;
	
	private MessageType(int value, int securityProfile){
		this.value = value;
		this.securityProfile = securityProfile;
	}
	
	public int getValue(){
		return value;
	}
	
	public int getSecurityProfile(){
		return securityProfile;
	}
	
	/**
	 * Method returning a SecurityProfile by it's byte value.
	 */
	public static MessageType getByValue(int value){
		for(MessageType next : MessageType.values()){
			if(next.value == value){
				return next;
			}
		}
		return null;
	}

}
