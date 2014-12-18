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
 *  none(0),
 *  circle(1),
 *  rectangle(2),
 *  polygon(3),
 *  id(4),
 *  reserved (240..255)
 * } RegionType;
 * </code>
 * <p>
 * This enumeration lists possible region types. Values in the range of 240 to 255 shall not be used as they are reserved for
 * internal testing purposes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum RegionType {
	none( 0),
	circle(1),
	rectangle(2),
	polygon(3),
	id(4);
	
	private int byteValue;
	
	RegionType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a Region Type by it's byte value.
	 */
	public static RegionType getByValue(int value){
		for(RegionType next : RegionType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}