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
package org.certificateservices.custom.c2x.asn1.coer;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;


/**
 * COER Encoding of a bit string.
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Section 13
 * <p>
 * <b>Important: a maximum bitstring of 64 bits are supported.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERBitString implements COEREncodable{
	

	private static final long serialVersionUID = 1L;

	protected long bitString;
	
	protected Integer length = null;
	protected boolean fixedSize = true;
	

	/**
	 * Constructor used when decoding a bit string of a fixed length.
	 * @param length the length of the bit string.
	 * @throws IOException if length was invalid.
	 */
	public COERBitString(Integer length) throws IOException {
		checkLength(null, length);
		this.length = length;
	}
	
	/**
	 * Constructor used when decoding a variable sized bit string.
	 */
	public COERBitString() {
		fixedSize = false;
	}
	
	/**
	 * Constructor used when encoding a bit string.
	 * <p>
	 * If setFlag methods should be used, set bitString to 0 initially and call setFlag for each position.
	 * <p>
	 * @param bitString the value of the string.
	 * @param length the length of the string.
	 * @param fixedSize if the size of the string is fixed or variable.
	 * @throws IOException if length was invalid.
	 */
	public COERBitString(long bitString, Integer length, boolean fixedSize) throws IOException {
		checkLength(bitString, length);
		this.bitString = bitString;
		this.length = length;
		this.fixedSize = fixedSize;
	}

	/**
	 * 
	 * @return true if this bit string has fixed size.
	 */
	public boolean isFixedSize() {
		return fixedSize;
	}

	/**
	 * 
	 * @return the bit string value.
	 */
	public long getBitString() {
		return bitString;
	}

	/**
	 * 
	 * @return the length of the bit string.
	 */
	public Integer getLenght() {
		return length;
	}
	
	/**
	 * Method that returns the bit at the given position
	 * @param position position in bit string 0 and up.
	 * @return true if bit is set.
	 * @throws IOException if position is out of bounds.
	 */
	public boolean getFlag(int position) throws IOException{
		if(position >= length){
			throw new IOException("Error getting flag from bit string position is out of bounds: " + position);
		}
		long mask = 1 << (length - (position +1));
		return (bitString & mask) > 0;
	}
	
	/**
	 * Method to set a given bit at the given position.
	 * Important: This method assumes the bit is 0 before calling, cannot unset a flag.
	 * @param position the position of the bit to set.
	 * @param flag true if bit at position should be set.
	 * @throws IOException if position is out of bounds.
	 */
	public void setFlag(int position, boolean flag) throws IOException{
		if(position >= length){
			throw new IOException("Error setting flag from bit string position is out of bounds: " + position);
		}
		if(flag){
			long mask = 1 << (length - (position +1));
			bitString |= mask;
		}
	}
	
	/**
	 * Help method that returns the minial number of octets needed for a fixed size encoding of the given bitstring value.
	 * @param bitString bit string value.
	 * @return minimal octets for fixed size encoding.
	 */
	public static int getMiminalOctetsForFixedSize(long bitString){
		if(bitString == 0){
			return 0;
		}
		int len = 1;
		
		BigInteger biBitString = BigInteger.valueOf(bitString);
		BigInteger value = BigInteger.valueOf(256);
		while(value.compareTo(biBitString) != 1 ){
			len++;
			value = value.shiftLeft(8);
		}
		
		return len;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		int unusedBits = 8 - length % 8;
		if(unusedBits == 8){
			unusedBits = 0;
		}
		int byteToWrite = (unusedBits == 0 ? length/8 : length/8 +1);
		if(fixedSize){
		    serialize(out, byteToWrite, unusedBits);
		}else{
			if(bitString == 0){
				COEREncodeHelper.writeLengthDeterminant(1, out);
				out.write(0);
			}else{
				COEREncodeHelper.writeLengthDeterminant(byteToWrite +1, out);
				out.write(unusedBits);
				serialize(out, byteToWrite, unusedBits);
			}
		}
	}
	
	private void checkLength(Long bitString,Integer length) throws IOException{
		if(length > 64){
			throw new  IOException("Error currently BitString COER implementation only supports length of 64 bits.");
		}
	}
	
	private void serialize(DataOutputStream out, int byteToWrite, int unusedBits) throws IOException {
		long bitStringData = bitString << unusedBits;
		
		byte[] val = BigInteger.valueOf(bitStringData).toByteArray();
		int signOctet = 0;
		if(val[0] == 0x00){
			signOctet++;
		}
	
		byte[] buffer =  new byte[byteToWrite];
		System.arraycopy(val, signOctet, buffer, buffer.length - (val.length -signOctet), val.length -signOctet);
		out.write(buffer);
	}
	

	@Override
	public void decode(DataInputStream in) throws IOException {
		if(fixedSize){
			deserializeFixedBitString(in);
		}else{
			deserializeVariableSizedBitString(in);
		}
	}

	private void deserializeFixedBitString(DataInputStream in) throws IOException {
		int unusedBits = 8- length % 8;
		if(unusedBits == 8){
			unusedBits = 0;
		}
		int bytesToRead = (unusedBits == 0 ? length/8 : length/8 +1);
		deserialize(in,bytesToRead,unusedBits);
		
	}
	
	private void deserializeVariableSizedBitString(DataInputStream in) throws IOException {
		int bytesToRead = COEREncodeHelper.readLengthDeterminantAsInt(in) -1;
		int unusedBits = in.read();
		if(bytesToRead != 0){
		  deserialize(in, bytesToRead, unusedBits);
		}else{
			bitString = 0;
		}
	}
	
	private void deserialize(DataInputStream in, int bytesToRead, int unusedBits) throws IOException {
		byte[] value = new byte[bytesToRead];
		in.read(value);
		BigInteger bigInteger = new BigInteger(1,value);
		bitString = bigInteger.longValue() >>> unusedBits;
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (bitString ^ (bitString >>> 32));
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
		COERBitString other = (COERBitString) obj;
		if (bitString != other.bitString)
			return false;
		return true;
	}



	@Override
	public String toString() {
		return "COERBitString [bitString=" + BigInteger.valueOf(bitString).toString(16) + ( length != null ?  ", length=" + length : "")
				+ "]";
	}

}
