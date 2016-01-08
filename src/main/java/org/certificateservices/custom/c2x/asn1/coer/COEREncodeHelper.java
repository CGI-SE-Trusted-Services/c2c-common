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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

/**
 * Class containing help methods for encoding lengt determinant and enumeration values.
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Sections 8.6 and 11.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COEREncodeHelper {
	
	public static final BigInteger BI_127 = BigInteger.valueOf(127);
	
	
	/**
	 * Returns an encoded length determinant according to section 8.6 in the ISO/IEC 8825-7:2015 specification
	 * @param length the length to encode
	 * @param dos the output stream to write the length determinant to.
	 * @return an encoded representation of the length.
	 */
	public static void writeLengthDeterminant(BigInteger length, DataOutputStream dos) throws IllegalArgumentException, IOException{
		if(length.compareTo(BigInteger.ZERO) == -1 ){
			throw new IllegalArgumentException("Error length determinant value cannot be negative");
		}
		encodeLengthDeterminantOrEnumeration(length,dos, true);
	}

	/**
	 * Returns an encoded length determinant according to section 8.6 in the ISO/IEC 8825-7:2015 specification
	 * @param length the length to encode
	 * @param dos the output stream to write the length determinant to.
	 * @return an encoded representation of the length.
	 */
	public static void writeLengthDeterminant(long length, DataOutputStream dos) throws IllegalArgumentException, IOException{
		writeLengthDeterminant(BigInteger.valueOf(length), dos);
	}
	
	
	/**
	 * Returns an encoded enumeration value according to section 11 in the ISO/IEC 8825-7:2015 specification
	 * @param value the value to encode
	 * @param dos the output stream to write the length determinant to.
	 * @return an encoded representation of the length.
	 */
	public static void writeEnumerationValue(BigInteger value, DataOutputStream dos) throws IllegalArgumentException, IOException{
		encodeLengthDeterminantOrEnumeration(value,dos, true);
	}

	/**
	 * Returns an encoded enumeration value according to section 11 in the ISO/IEC 8825-7:2015 specification
	 * @param value the value to encode
	 * @param dos the output stream to write the length determinant to.
	 * @return an encoded representation of the length.
	 */
	public static void writeEnumerationValue(long value, DataOutputStream dos) throws IllegalArgumentException, IOException{
		writeEnumerationValue(BigInteger.valueOf(value), dos);
	}
	
	/**
	 * Returns an encoded enumeration value according to section 11 in the ISO/IEC 8825-7:2015 specification
	 * @param value the enumeration to encode
	 * @param dos the output stream to write the length determinant to.
	 * @return an encoded representation of the length.
	 */
	public static void writeEnumerationValue(COEREnumeration value, DataOutputStream dos) throws IllegalArgumentException, IOException{
		writeEnumerationValue(BigInteger.valueOf(value.ordinal()), dos);
	}

	
	/**
	 * Common method to calculate length determinant or Enumeration value.
	 * 
	 * @param value the value to encode
	 * @param dos the output stream to write the value to.
	 * @param isLengthDeterminant true if it should be encoded as length determinant otherwise false for enumeration.
	 */
	private static void encodeLengthDeterminantOrEnumeration(BigInteger value, DataOutputStream dos, boolean isLengthDeterminant) throws IllegalArgumentException, IOException{
		if(value.compareTo(BigInteger.ZERO) != -1 && value.compareTo(BI_127) != 1){
			dos.write(value.toByteArray());
			return;
		}
		byte[] valueAsOctets = value.toByteArray();
		if(isLengthDeterminant){
			if(valueAsOctets.length > 127){
				throw new IllegalArgumentException("Error to long length determinant value, must be less than 2^1016-1");
			}
		}else{
			if(valueAsOctets.length > 127){
				throw new IllegalArgumentException("Error to enumeration value, must be between -2^1015 and 2^1015");
			}
		}
		
		int signOctet = 0;
		if(valueAsOctets[0] == 0x00 && valueAsOctets.length > 1){
			signOctet++;
		}
		
		int lengthIndicator = (valueAsOctets.length - signOctet) | 0x80;
		dos.write(lengthIndicator);
		dos.write(valueAsOctets, signOctet, valueAsOctets.length -signOctet);
	}
	
	/**
	 * Method that decodes data into a length determinant according to section 8.6  in the ISO/IEC 8825-7:2015 specification
	 * @param dis the input stream to read the length determinant from.
	 * @return a decoded representation of the length.
	 */
	public static BigInteger readLengthDeterminant(DataInputStream dis) throws IOException{
		return decodeLengthDeterminantOrEnumeration(dis, true);
	}
	
	/**
	 * Method that decodes data into a length determinant according to section 8.6  in the ISO/IEC 8825-7:2015 specification
	 * @param dis the input stream to read the length determinant from.
	 * @return a decoded representation of the length.
	 */
	public static long readLengthDeterminantAsLong(DataInputStream dis) throws IOException{
		return readLengthDeterminant(dis).longValue();
	}
	
	/**
	 * Method that decodes data into a enumeration value according to section 11  in the ISO/IEC 8825-7:2015 specification
	 * @param dis the input stream to read the value from.
	 * @return a decoded representation of the length.
	 */
	public static int readLengthDeterminantAsInt(DataInputStream dis) throws IOException{
		return readLengthDeterminant(dis).intValue();
	}
	
	/**
	 * Method that decodes data into a enumeration value according to section 8.6  in the ISO/IEC 8825-7:2015 specification
	 * @param dis the input stream to read the length determinant from.
	 * @return a decoded representation of the length.
	 */
	public static BigInteger readEnumerationValue(DataInputStream dis) throws IOException{
		return decodeLengthDeterminantOrEnumeration(dis, false);
	}

	/**
	 * Method that decodes data into a enumeration value according to section 11  in the ISO/IEC 8825-7:2015 specification
	 * @param dis the input stream to read the value from.
	 * @return a decoded representation of the value.
	 */
	public static long readEnumerationValueAsLong(DataInputStream dis) throws IOException{
		return readEnumerationValue(dis).longValue();
	}
	
	/**
	 * Method that decodes data into a length determinant according to section 11  in the ISO/IEC 8825-7:2015 specification
	 * @param dis the input stream to read the value from.
	 * @return a decoded representation of the value.
	 */
	public static int readEnumerationValueAsInt(DataInputStream dis) throws IOException{
		return readEnumerationValue(dis).intValue();
	}
	
	/**
	 * Help method to read and enumeration value to a enumeration constant for supplied Enum class.
	 * @param enumeration the enum to match ordinal of encoded enumeration value to.
	 * @param dis the input stream to read the value from.
	 * @return a decoded representation of the value.
	 */
	public static COEREnumeration readEnumeratonValueAsEnumeration(Class<COEREnumeration> enumeration, DataInputStream dis) throws IOException{
		int ordinal = readEnumerationValueAsInt(dis);
		for(COEREnumeration next : enumeration.getEnumConstants()){
			if(next.ordinal() == ordinal){
				return next;
			}
		}
		throw new IOException("Error decoding COER enumeration, no matching enumeration value exists for ordinal: " + ordinal);
	}

	/**
	 * Help method to perform java serialization of coer objects used for deep cloning.
	 */
	public static byte[] serialize(COEREncodable object) throws IllegalArgumentException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			ObjectOutputStream dos = new ObjectOutputStream(baos);
			dos.writeObject(object);
		} catch (IOException e) {
			throw new IllegalArgumentException("Error serializing COER object during deep clone: " + e.getMessage());
		}
		
		return baos.toByteArray();
	}
	
	/**
	 * Help method to perform java deserialization of coer objects used for deep cloning.
	 */
	public static COEREncodable deserialize(byte[] serializedData) throws IllegalArgumentException{
		try {
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
			return (COEREncodable) ois.readObject();
		} catch (Exception e) {
			throw new IllegalArgumentException("Error deserializing COER object during deep clone: " + e.getMessage());
		}
	}
	
	/**
	 * Help method to decode length determinant or enumeration
	 * @param dis input stream
	 * @param isLengthDeterminant if value is a length determinant otherwise false
	 * 
	 */
	private static BigInteger decodeLengthDeterminantOrEnumeration(DataInputStream dis, boolean isLengthDeterminant) throws IOException{
		int firstVal = dis.read();
		if(firstVal <= 127){
			return BigInteger.valueOf(firstVal);
		}
		int lengthIndicator = firstVal & 0x7f;
		if(isLengthDeterminant){
			byte[] lengthValue = new byte[lengthIndicator +1];
			dis.read(lengthValue, 1, lengthIndicator);
			return new BigInteger(1,lengthValue);
		}else{
			byte[] lengthValue = new byte[lengthIndicator];
			dis.read(lengthValue, 0, lengthIndicator);
			return new BigInteger(lengthValue);
		}
	}
	
	
		
}
