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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * This uint16 encodes the duration of a time span (e.g. a certificate's validity). The first three bits shall encode the units
 * as given in table 3. The remaining 13 bits shall be treated as an integer encoded in network byte order.
 * 
 * @author Philip Vendil
 *
 */
public class Duration implements Encodable{
	
	public enum Unit{
		SECONDS(0,1L, 0x0),
		MINUTES(1,60L, 0x2000),
		HOURS(2,3600L, 0x4000),
		BLOCK_60_HOUR(3,216000L,0x6000),
		YEARS(4,31556925L,0x8000);
		
		private int byteValue;
		private long seconds;
		private int unitMask;
		
		Unit(int byteValue, long seconds,int unitMask){
			this.byteValue = byteValue;
			this.seconds = seconds;
			this.unitMask = unitMask;
		}
		
		public int getByteValue(){
			return byteValue;
		}
		
		public long getSeconds(){
			return seconds;
		}
		
		public int getUnitMask(){
			return unitMask;
		}
		
		/**
		 * Method returning a Unit from it's encoded duration value
		 */
		public static Unit getByEncodedDuration(int value){
			int decodedValue = (value >> 13)  & 0x7;
			for(Unit next : Unit.values()){
				if(next.byteValue == decodedValue){
					return next;
				}
			}
			return null;
		}
	}
	
	private int encodedDuration;
	
	/**
	 * Constructor for creating a duration object from a raw byte value with unit encoding already done.
	 * 
	 * @param value the duration value
	 * @param unit the unit related to the duration value
	 */
	public Duration(int value, Unit unit) {
		if(value > 8192){
			throw new IllegalArgumentException("Error invalid duration value, must be less that 8193, try to change unit.");
		}
		this.encodedDuration = value | unit.getUnitMask();
	}
	
	/**
	 * Constructor for creating a duration object from a raw byte value with unit encoding already done.
	 * 
	 * @param encodedDuration the raw duration value.
	 */
	public Duration(int encodedDuration) {
		this.encodedDuration = encodedDuration;
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public Duration(){
	}
	
	/** 
	 * @return the unit of this duration
	 */
	public Unit getUnit(){
		return Unit.getByEncodedDuration(encodedDuration);
	}
	
	/**
	 * 
	 * @return the decoded value of the duration.
	 */
	public int getDurationValue(){
		return encodedDuration & 0x1FFF;
	}
	
	/**
	 * 
	 * @return the encoded unit and value of the duration.
	 */
	public int getEncodedDuration(){
		return encodedDuration;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(ByteBuffer.allocate(4).putInt(encodedDuration).array(),2,2);		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		byte[] data = new byte[4];
		in.read(data,2,2);
		encodedDuration = ByteBuffer.wrap(data).getInt();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + encodedDuration;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Duration other = (Duration) obj;
		if (encodedDuration != other.encodedDuration)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Duration [encodedDuration=" + encodedDuration + " (value=" + getDurationValue() + " " + getUnit() + ")]";
	}


}
