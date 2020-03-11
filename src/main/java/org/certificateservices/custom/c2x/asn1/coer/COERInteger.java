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
import java.util.Arrays;

/**
 * COER encoding of an Integer
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Section 10
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERInteger implements COEREncodable{
	
	private static final long serialVersionUID = 1L;
	
	protected BigInteger value;
	
	protected BigInteger minValue = null;
	protected BigInteger maxValue = null;
	
	private static final BigInteger TWO_PWR_8_MINUS_1 = BigInteger.valueOf(255); 
	private static final BigInteger TWO_PWR_16_MINUS_1 = BigInteger.valueOf(65535);
	private static final BigInteger TWO_PWR_32_MINUS_1 = BigInteger.valueOf(4294967295L);
	private static final BigInteger TWO_PWR_64_MINUS_1 = new BigInteger("18446744073709551615");
	
	
	private static final BigInteger NEGATIVE_TWO_PWR_7 = BigInteger.valueOf(-128);
	private static final BigInteger TWO_PWR_7_MINUS_1  = BigInteger.valueOf(127);
	
	private static final BigInteger NEGATIVE_TWO_PWR_15 = BigInteger.valueOf(-32768);
	private static final BigInteger TWO_PWR_15_MINUS_1  = BigInteger.valueOf(32767);
	
	private static final BigInteger NEGATIVE_TWO_PWR_31 = BigInteger.valueOf(-2147483648);
	private static final BigInteger TWO_PWR_31_MINUS_1  = BigInteger.valueOf(2147483647);
	
	private static final BigInteger NEGATIVE_TWO_PWR_63 = new BigInteger("-9223372036854775808");
	private static final BigInteger TWO_PWR_63_MINUS_1  = new BigInteger("9223372036854775807");
	
	/**
	 * Constructor when decoding an integer with no known min or max value.
	 */
	public COERInteger(){
	}
	
	/**
	 * Constructor when decoding and integer with known min or max value.
	 * 
	 * @param minValue the minimal value of the integer, or null if not known.
	 * @param maxValue the maximal value of the integer, or null if not known.
	 */
	public COERInteger(BigInteger minValue, BigInteger maxValue){
		this.minValue = minValue;
		this.maxValue = maxValue;
	}
	
	/**
	 * Constructor when decoding and integer with known min or max value.
	 * 
	 * @param minValue the minimal value of the integer, or null if not known.
	 * @param maxValue the maximal value of the integer, or null if not known.
	 */
	public COERInteger(long minValue, long maxValue){
		this.minValue = BigInteger.valueOf(minValue);
		this.maxValue = BigInteger.valueOf(maxValue);
	}
	
	/**
	 * Constructor used when encoding integer with no known min or max value.
	 * 
	 * @param value the integer value.
	 */
	public COERInteger(BigInteger value) {
		this.value = value;
	}
	
	/**
	 * Constructor used when encoding integer with known min or max value.
	 * 
	 * @param value the integer value.
	 * @param minValue the minimal value of the integer, or null if not known.
	 * @param maxValue the maximal value of the integer, or null if not known.
	 * @throws IllegalArgumentException if invalid parameters were specified.
	 */
	public COERInteger(BigInteger value, BigInteger minValue, BigInteger maxValue) throws IllegalArgumentException{
		this.value = value;
		this.minValue = minValue;
		this.maxValue = maxValue;
		
		if(minValue != null && value.compareTo(minValue) == -1){
			throw new IllegalArgumentException("Error given value " + value + " is less than minimal value of " + minValue);
		}
		if(maxValue != null && value.compareTo(maxValue) == 1){
			throw new IllegalArgumentException("Error given value " + value + " is more than maximal value of " + maxValue);
		}
	}
	
	/**
	 * Constructor used when encoding integer with no known min or max value.
	 * 
	 * @param value the integer value.
	 */
	public COERInteger(long value) {
		this.value = BigInteger.valueOf(value);
	}
	
	/**
	 * Constructor used when encoding integer with known min or max value.
	 * 
	 * @param value the integer value.
	 * @param minValue the minimal value of the integer, or null if not known.
	 * @param maxValue the maximal value of the integer, or null if not known.
	 * @throws IllegalArgumentException if invalid parameters were specified.
	 */
	public COERInteger(long value, long minValue, long maxValue) throws IllegalArgumentException{
		this(BigInteger.valueOf(value),BigInteger.valueOf(minValue),BigInteger.valueOf(maxValue));
	}

	/**
	 * 
	 * @return returns the value of this integer.
	 */
	public BigInteger getValue() {
		return value;
	}
	
	/**
	 * 
	 * @return returns the value of this integer (use only if it's certain the integer fits within a signed java long)
	 */
	public long getValueAsLong() {
		return value.longValue();
	}

	/**
	 * 
	 * @return the minimal value boundary, or null if not known.
	 */
	public BigInteger getMinValue() {
		return minValue;
	}

	/**
	 * 
	 * @return the maximal value boundary, or null if not known.
	 */
	public BigInteger getMaxValue() {
		return maxValue;
	}
	
	/**
	 * 
	 * @return true if this integer is encoded as an unsigned.
	 */
	public boolean isUnsigned(){
		if(minValue != null){
			if(minValue.compareTo(BigInteger.ZERO) != -1){
					return true;
			}
		}
		
		return false;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		if(isUnsigned()){
			serializeUnsigned(out);
		}else{
			serializeSigned(out);
		}
		
	}
	
	private void serializeUnsigned(DataOutputStream out) throws IOException {
		byte[] val = value.toByteArray();

		int signOctet = 0;
		if(val[0] == 0x00 && val.length > 1){
			signOctet++;
		}
		
		if(isUnsignedAndLessOrEqualThan(TWO_PWR_64_MINUS_1)){
			byte[] buffer = new byte[getUnsignedBufferSize()];
			System.arraycopy(val, signOctet, buffer, buffer.length - (val.length -signOctet), val.length -signOctet);
			out.write(buffer);
		}else{
		    COEREncodeHelper.writeLengthDeterminant(val.length - signOctet, out);
			out.write(val, signOctet, val.length -signOctet);
		}
	}
	
	private void serializeSigned(DataOutputStream out) throws IOException {
		byte[] val = value.toByteArray();

		int signOctet = 0;
		if(val[0] == 0x00 && val.length > 1){
			signOctet++;
		}
		
		if(isSignedAndBetween(NEGATIVE_TWO_PWR_63, TWO_PWR_63_MINUS_1)){
			byte[] buffer = new byte[getSignedBufferSize()];
			if(value.signum() ==  -1) {
				Arrays.fill(buffer, (byte) -1);
			}
			System.arraycopy(val, signOctet, buffer, buffer.length - (val.length -signOctet), val.length -signOctet);
			out.write(buffer);
		}else{
		    COEREncodeHelper.writeLengthDeterminant(val.length-signOctet, out);
			out.write(val, signOctet, val.length -signOctet);
		}
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		if(isUnsigned()){
			deserializeUnsigned(in);
		}else{
			deserializeSigned(in);
		}
	}
	
	private void deserializeUnsigned(DataInputStream in) throws IOException {
		
		int bufferSize = 0;
		if(isUnsignedAndLessOrEqualThan(TWO_PWR_64_MINUS_1)){
			bufferSize = getUnsignedBufferSize();
		}else{
			bufferSize = COEREncodeHelper.readLengthDeterminantAsInt(in);
			if(bufferSize > 256 || bufferSize < 1){
				throw new IOException("Invalid COERInteger length determinant: " + bufferSize);
			}
		}
		byte[] buffer = new byte[bufferSize];
		in.read(buffer);
		value = new BigInteger(1, buffer);
	}
	
	private void deserializeSigned(DataInputStream in) throws IOException {
		int bufferSize = 0;
		if(isSignedAndBetween(NEGATIVE_TWO_PWR_63, TWO_PWR_63_MINUS_1)){
			bufferSize = getSignedBufferSize();
		}else{
			bufferSize = COEREncodeHelper.readLengthDeterminantAsInt(in);
			if(bufferSize > 256 || bufferSize < 1){
				throw new IOException("Invalid COERInteger length determinant: " + bufferSize);
			}
		}
		byte[] buffer = new byte[bufferSize];
		in.read(buffer);
		value = new BigInteger(buffer);
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
		if (!(obj instanceof COERInteger))
			return false;
		COERInteger other = (COERInteger) obj;
		if (value == null) {
			if (other.value != null)
				return false;
		} else if (!value.equals(other.value))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "COERInteger [value=" + value + "]";
	}


	private boolean isUnsignedAndLessOrEqualThan(BigInteger comparison){
		if(minValue != null && maxValue != null){
			if(minValue.compareTo(BigInteger.ZERO) != -1){
				if(maxValue.compareTo(comparison) != 1){
					return true;
				}
			}
		}
		
		return false;
	}
	
	private boolean isSignedAndBetween(BigInteger minComparision, BigInteger maxComparison){
		if(minValue != null && maxValue != null){
			return minValue.compareTo(minComparision) != -1 && maxValue.compareTo(maxComparison) != 1;
		}
		
		return false;
	}
	
	

	
	private int getUnsignedBufferSize(){
		if(isUnsignedAndLessOrEqualThan(TWO_PWR_8_MINUS_1)){
			return 1;	
		}
		if(isUnsignedAndLessOrEqualThan(TWO_PWR_16_MINUS_1)){
			return 2;	
		}
		if(isUnsignedAndLessOrEqualThan(TWO_PWR_32_MINUS_1)){
			return 4;
		}
		return 8;
	}
	
	private int getSignedBufferSize(){
		if(isSignedAndBetween(NEGATIVE_TWO_PWR_7, TWO_PWR_7_MINUS_1)){
			return 1;	
		}
		if(isSignedAndBetween(NEGATIVE_TWO_PWR_15, TWO_PWR_15_MINUS_1)){
			return 2;	
		}
		if(isSignedAndBetween(NEGATIVE_TWO_PWR_31, TWO_PWR_31_MINUS_1)){
			return 4;
		}
		return 8;
	}
}
