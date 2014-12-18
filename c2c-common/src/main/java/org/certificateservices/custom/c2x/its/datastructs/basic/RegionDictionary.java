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
 *  iso_3166_1(0),
 *  un_stats(1),
 * } RegionDictionary;
 * </code>
 * <p>
 * This enumeration lists possible region types. Values in the range of 240 to 255 shall not be used as they are reserved for
 * internal testing purposes.This enumeration lists dictionaries containing two-octet records of globally defined regions. The dictionary that
 * corresponds to iso_3166_1 shall contain values that correspond to numeric country codes as defined in
 * ISO 3166-1 [3]. The dictionary that corresponds to un_stats shall contain values as defined by the United Nations
 * Statistics Division, which is a superset of ISO 3166-1 [3] including compositions of regions.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum RegionDictionary {
	iso_3166_1( 0),
	un_stats(1);
	
	private int byteValue;
	
	RegionDictionary(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a Region Dictionary by it's byte value.
	 */
	public static RegionDictionary getByValue(int value){
		for(RegionDictionary next : RegionDictionary.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}