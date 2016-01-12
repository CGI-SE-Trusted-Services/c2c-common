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
package org.certificateservices.custom.c2x.asn1.coer

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmAlgorithm;

import spock.lang.IgnoreRest;
import spock.lang.Specification
import spock.lang.Unroll;

class COEREncodeHelperSpec extends BaseStructSpec {

	
	@Unroll
	def "Verify that writeLengthDeterminant generates encoding #encoded for value #value and readLengthDeterminant converts it back correctly"(){
		setup:
		ByteArrayOutputStream baos = new ByteArrayOutputStream()
		DataOutputStream dos = new DataOutputStream(baos);
		when:
		COEREncodeHelper.writeLengthDeterminant(new BigInteger(value), dos)
		dos.close();
		byte[] encodedData = baos.toByteArray()
		then:
		new String(Hex.encode(encodedData)) == encoded
		
		when:
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))
		BigInteger decoded = COEREncodeHelper.readLengthDeterminant(dis)
		then:
		decoded.equals(new BigInteger(value))
		
		where:
		encoded              | value
		"00"                 | "0"
		"01"                 | "1"
		"7f"                 | "127"
		"8180"               | "128"
		"85017f65c4cb"       | "6432343243"
		"8802ad5adfd445b0cb" | "192910276432343243"
		
	}
	
	@Unroll
	def "Verify that writeLengthDeterminant generates encoding #encoded for value #value and readLengthDeterminant converts it back correctly for long values as well"(){
		setup:
		ByteArrayOutputStream baos = new ByteArrayOutputStream()
		DataOutputStream dos = new DataOutputStream(baos);
		when:
		COEREncodeHelper.writeLengthDeterminant(value, dos)
		dos.close();
		byte[] encodedData = baos.toByteArray()
		then:
		new String(Hex.encode(encodedData)) == encoded
		
		when:
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))
		long decoded = COEREncodeHelper.readLengthDeterminantAsLong(dis)
		then:
		decoded == value
		
		where:
		encoded              | value
		"85017f65c4cb"       | 6432343243L
		
	}
	
	@Unroll
	def "Verify that writeEnumerationValue generates encoding #encoded for value #value and readEnumerationValue converts it back correctly"(){
		setup:
		ByteArrayOutputStream baos = new ByteArrayOutputStream()
		DataOutputStream dos = new DataOutputStream(baos);
		when:
		COEREncodeHelper.writeEnumerationValue(new BigInteger(value), dos)
		dos.close();
		byte[] encodedData = baos.toByteArray()
		then:
		new String(Hex.encode(encodedData)) == encoded
		
		when:
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))
		BigInteger decoded = COEREncodeHelper.readEnumerationValue(dis)
		then:
		decoded.equals(new BigInteger(value))
		
		where:
		encoded              | value
		"00"                 | "0"
		"01"                 | "1"
		"7f"                 | "127"
		"8180"               | "-128"
		"84fe9ac1a9"         | "-23412311"
		"85017f65c4cb"       | "6432343243"
		"8802ad5adfd445b0cb" | "192910276432343243"
		
	}
	
	@Unroll
	def "Verify that writeEnumerationValue generates encoding #encoded for value #value and readEnumerationValue converts it back correctly for long values as well"(){
		setup:
		ByteArrayOutputStream baos = new ByteArrayOutputStream()
		DataOutputStream dos = new DataOutputStream(baos);
		when:
		COEREncodeHelper.writeEnumerationValue(value, dos)
		dos.close();
		byte[] encodedData = baos.toByteArray()
		then:
		new String(Hex.encode(encodedData)) == encoded
		
		when:
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))
		long decoded = COEREncodeHelper.readEnumerationValueAsLong(dis)
		then:
		decoded == value
		
		where:
		encoded              | value
		"84fe9ac1a9"         | -23412311L
		
	}

	def "Verify that writeLengthDeterminant doesn't accept negative numbers"(){		
		setup:
		ByteArrayOutputStream baos = new ByteArrayOutputStream()
		DataOutputStream dos = new DataOutputStream(baos);
		when:
		COEREncodeHelper.writeLengthDeterminant(-1, dos)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify that write and read enumeration value from COEREnumeration is correct encoded and decoded"(){
		setup:
		ByteArrayOutputStream baos = new ByteArrayOutputStream()
		DataOutputStream dos = new DataOutputStream(baos);
		when:
		COEREncodeHelper.writeEnumerationValue(SymmAlgorithm.aes128Ccm, dos)
		dos.close();
		byte[] encodedData = baos.toByteArray()
		then:
		new String(Hex.encode(encodedData)) == "00"
		
		when:
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))
		COEREnumerationType v = COEREncodeHelper.readEnumeratonValueAsEnumeration(SymmAlgorithm.class,dis)
		then:
		v == SymmAlgorithm.aes128Ccm
		
	
	}
	
	def "Verify that padZerosToByteArray inserts required number of zeros in beginning of byte array"(){
		byte[] data1 = Hex.decode("1000");
		
		expect:
		COEREncodeHelper.padZerosToByteArray(null, 5) == null
		new String(Hex.encode(COEREncodeHelper.padZerosToByteArray(data1, 5))) == "0000001000"
		new String(Hex.encode(COEREncodeHelper.padZerosToByteArray(data1, 2))) == "1000"
	}


}
