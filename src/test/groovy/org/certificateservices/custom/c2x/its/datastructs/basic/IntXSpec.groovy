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
package org.certificateservices.custom.c2x.its.datastructs.basic

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class IntXSpec extends BaseStructSpec{
	
	

	@Unroll
	def "Verify getNumberOfOctets for number: #number has number of octets: #octets"(){
		expect:
		(new IntX()).getNumberOfOctets(number) == octets
		where:
		number         | octets
		0b01000001     | 1
		0b00000001     | 1
		0b10000001     | 2
		0b11010001     | 3
		0b11010001     | 3
		0b11101001     | 4
		0b11110001     | 5
		0b11111001     | 6
		0b11111101     | 7
		0b11111110     | 8		
	}
	
	@Unroll
	def "Verify getFirstByteValue for number: #number where: #removeNumberOfBits is removed becomes: #firstByteValue"(){
		expect:
		(new IntX()).getFirstByteValue((byte) number, removeNumberOfBits) == firstByteValue
		where:
		number         | removeNumberOfBits | firstByteValue
		0b00000001     | 1                  | 1
		0b10000001     | 1                  | 1
		0b11000001     | 2                  | 1
		0b11000010     | 2                  | 2
		0b11100010     | 3                  | 2
		0b11111010     | 5                  | 2
		0b11111110     | 6                  | 2
		0b11111111     | 7                  | 1
		0b11111111     | 8                  | 0
		0b11101111     | 4                  | 15
		0b01111111     | 1                  | 127
		
	}

	@Unroll
	def "Verify that deserialize decodes the value 0x#valueInHex properly into: #expectedValue"(){
		expect:
		(deserializeFromHex(new IntX(), valueInHex)).value.toLong() == expectedValue
		
		where:
		valueInHex      | expectedValue
		"00"            | 0L
		"01"            | 1L
		"0a"            | 10L
		"8888"          | 2184L
	}

	@Unroll
	def "Verify that encodeValue encodes the value 0x#value properly into: 0x#expectedValue"(){
		expect:
		new String(Hex.encode((new IntX(new BigInteger(value,16))).encodeValue())) == expectedValue
		
		where:
		value       | expectedValue
		"00"        | "00"              // As interpreted by the Spec (not sure if this is correct encoding)
		"0a"        | "0a"              // According to Spec
		"0888"      | "8888"            // According to Spec 
		"10000"     | "c10000"          // As interpreted by the Spec (not sure if this is correct encoding)
		"db3bfd"    | "e0db3bfd"        // As interpreted by the Spec (not sure if this is correct encoding)
		"80"        | "8080"
	}
	
	def "Verify that encodeValue throws NumberFormatException"(){
		when:
		(new IntX(new BigInteger("FFFFFFFFFFFFFFFF",16))).encodeValue();
		then:
		thrown(IOException)
	}
	
	@Unroll
	def "Verify that serialize ecodes the value 0x#valueInHex properly into: 0x#expectedValue"(){
		expect:
		serializeToHex(new IntX(new BigInteger(valueInHex,16))) == expectedValue
		
		where:
		valueInHex      | expectedValue
		"00"            | "00"
		"0a"            | "0a"              // According to Spec
		"0888"          | "8888"            // According to Spec
	}
	
	def "Verify hashCode and equals"(){
		setup:
		def o1  = new IntX(new BigInteger(141640715));
		def o2  = new IntX(new BigInteger(141640715));
		def o3  = new IntX(new BigInteger(141640716));
		expect:
		o1 == o2
		o1 != o3
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new IntX(new BigInteger(141640715)).toString() == "IntX [value=141640715]"
	}
	
	def "Verify long value constructor"(){
		expect:
		new IntX(1234L).value.longValue() == 1234L
	}
}
