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
import java.math.BigInteger;

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * This data type encodes an integer of variable length. The length of this integer is encoded by a number of 1 bit followed
 * by a 0 bit, where the number of 1 bit is equal to the number of additional octets used to encode the integer besides those
 * used (partially) to encode the length.
 * 
 * EXAMPLE: 00001010 encodes the integer 10, while 10001000 10001000 encodes the integer 2 184. The bits
 * encoding the length of the element are colored with a grey background.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class IntX implements Encodable{
	
	BigInteger value;
	
	/**
	 * Main constructor.
	 * 
	 * @param value java integer representation of the value.
	 */
	public IntX(BigInteger value){
		this.value = value;
	}
	
	/**
	 * Constructor from a long value.
	 * 
	 * @param value java integer representation of the value.
	 */
	public IntX(long value){
		this.value = BigInteger.valueOf(value);
	}
	
	/**
	 * Constructor used during serializing.
	 */
	public IntX(){}
	
	/**
	 * Returns a java big integer representation of the value. 
	 * @return value;
	 */
	public BigInteger getValue(){
		return value;
	}
	
	/**
	 * Returns the IntX value as integer, only use if you know that the ITS value fits with an integer.
	 * @return the IntX value as integer
	 */
	public int asInt(){
		return value.intValue();
	}

	/**
	 * Returns the IntX value as long, only use if you know that the ITS value fits with an long.
	 * @return the IntX value as long
	 */
	public long asLong(){
		return value.longValue();
	}
	
	/**
	 * 
	 * @return  a byte array of the value in intX encoded format.
	 * @throws IOException if value is to large or in other was unsupported by encoding algorithm.
	 */
	public byte[] encodeValue() throws IOException{
		byte[] data = value.toByteArray();
		int n = data.length;
		if(n > 8){
			throw new IOException("Error to large intX value, only up to 8 octets is supported");
		}
		int maxFirstByteValue = (int) Math.pow(2, (8-n));
		if(data[0] <  maxFirstByteValue){
			byte zeroMask = (byte) (0xFF >> n);
		    data[0] =   (byte) (data[0]  & zeroMask);
		    int oneMask = 0xFF << (9-n);
		    data[0] =   (byte) (data[0]  | oneMask);
		    return data;
		}
		
		byte[] newValue = new byte[n+1];
		for(int i = 0; i < n ; i++ ){
			newValue[i+1] = data[i];
		}
		
		newValue[0] = (byte) (0xFF << (8-n));
		
		return newValue;
	}
	


	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(encodeValue());
		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		byte firstByteValue = in.readByte();
		int numOfOctets = getNumberOfOctets(firstByteValue);
		
		byte firstValue = getFirstByteValue(firstByteValue,numOfOctets); 
		byte[] data = new byte[numOfOctets];
		data[0] = firstValue;
		for(int i=1; i < numOfOctets; i++){
			data[i] = in.readByte();
		}
		
		value = new BigInteger(data);
	}
	
	/**
	 * Removes the bits indicating the number of octets used for the number.
	 * @param firstByteValue the first octet byte value.
	 * @param numOfOctets the number of octets.
	 * @return the remaining value of the octet.
	 */
	private byte getFirstByteValue(byte firstByteValue, int numOfOctets) {
		int mask = 0xFF >>  numOfOctets;		
		return (byte) (firstByteValue & mask);
	}

	/**
	 * Method that traverses the first byte from most significant bit to check the size of the integer value.
	 */
	private int getNumberOfOctets(int value){
		int position=7;
		while(true){
			if((value >> position & 1) == 0){
				break;
			}else{
				position--;
			}
		}
		return 8-position;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((value == null) ? 0 : value.hashCode());
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
		IntX other = (IntX) obj;
		if (value == null) {
			if (other.value != null)
				return false;
		} else if (!value.equals(other.value))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "IntX [" + value + "]";
	}


}
