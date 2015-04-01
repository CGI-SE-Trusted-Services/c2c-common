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
 *  x_coordinate_only(0),
 *  compressed_lsb_y_0(2),
 *  compressed_lsb_y_1(3),
 *  uncompressed(4),
 *  (2^8-1)
 * } EccPointType;
 * </code>
 * <p>
 * This enumeration lists supported ECC key types.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum EccPointType {
	x_coordinate_only( 0),
	compressed_lsb_y_0( 2),
	compressed_lsb_y_1( 3),
	uncompressed( 4);
	
	private int byteValue;
	
	EccPointType(int byteValue){
		this.byteValue = byteValue;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	/**
	 * Method returning a ecc point by it's byte value.
	 */
	public static EccPointType getByValue(int value){
		for(EccPointType next : EccPointType.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}