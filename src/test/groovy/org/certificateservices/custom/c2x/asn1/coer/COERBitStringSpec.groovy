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


import org.certificateservices.custom.c2x.common.BaseStructSpec

import spock.lang.IgnoreRest;
import spock.lang.Specification
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.asn1.coer.COERBitString.*

class COERBitStringSpec extends BaseStructSpec {
	
	
	
	@Unroll
	def "Verify that COERBitString with value #value returns #encoded encoded and decoded #encoded generates a #value value with length #length and fixed size :#fixedSize"(){
		when:
		COERBitString coerBitString = new COERBitString(value, length, fixedSize)
		then:
		serializeToHex(coerBitString) == encoded
		
		when:
		coerBitString = new COERBitString(length)
		coerBitString.fixedSize = fixedSize
		coerBitString = deserializeFromHex(coerBitString, encoded)
		then:
		coerBitString.bitString == value
		
		where:
		encoded                                     | value                   | length       | fixedSize            
		"00"                                        | 0L                      | 8            | true
		"ff"                                        | 255L                    | 8            | true
		"0a"                                        | 10L                     | 8            | true
		"1001"                                      | 0x1001                  | 16           | true
		"fe1001"                                    | 0xfe1001                | 24           | true
		"00fe1001"                                  | 0xfe1001                | 32           | true
		"0000000000fe1001"                          | 0xfe1001                | 64           | true
		"00fe100100fe1001"                          | 0xfe100100fe1001        | 64           | true
		"00"                                        | 0L                      | 6            | true
		"04"                                        | 1L                      | 6            | true
		"10"                                        | 1L                      | 4            | true
		"000000a0"                                  | 40L                     | 30           | true
		"0100"                                      | 0L                      | 8            | false
		"020001"                                    | 1L                      | 8            | false
		"020204"                                    | 1L                      | 6            | false
		"0502000000a0"                              | 40L                     | 30           | false
		"090000fe100100fe1001"                      | 0xfe100100fe1001L       | 64           | false
	}
	
	
	def "Verify that getFlag and setFlag sets correct bits"(){
	    when:
		// start with all flags not set.
		COERBitString b1 = new COERBitString(0, 8, true)
		b1.setFlag(0,true);
		b1.setFlag(1, false);
		b1.setFlag(2, true);
		then:
		b1.bitString == 0b10100000
		b1.getFlag(0)
		!b1.getFlag(1)
		b1.getFlag(2)
		when:
		// start with all flags not set.
		COERBitString b2 = new COERBitString(0, 5, true)
		b2.setFlag(0,true);
		b2.setFlag(1, false);
		b2.setFlag(2, true);
		then:
		b2.bitString == 0b10100
		b2.getFlag(0)
		!b2.getFlag(1)
		b2.getFlag(2)
		// start with all flags not set.
		COERBitString b3 = new COERBitString(0, 15, true)
		b3.setFlag(0,true);
		b3.setFlag(1, false);
		b3.setFlag(2, true);
		b3.setFlag(9, true);
		then:
		b3.bitString == 0b101000000100000
		b3.getFlag(0)
		!b3.getFlag(1)
		b3.getFlag(2)
		b3.getFlag(9)
	}
	

	def "Verify that length larger that 64  in constructor throws a IllegalArgumentException"(){
		when:
		new COERBitString(5L,65, false)
		then:
		thrown IllegalArgumentException
	}

	
	def "Verify that constuctor and getter"(){
		expect:
		new COERBitString(5L,8,false).getBitString() == 5L
		new COERBitString(5L,16, false).getBitString() == 5L
		new COERBitString(5L,8, false).getLenght() == 8
		new COERBitString(5L,8, true).isFixedSize()
		!new COERBitString().isFixedSize()
		new COERBitString(8).isFixedSize()
	}
	
	def "Verify equals and hashcode"(){
		setup:
		COERBitString first = new COERBitString(5L,8,false)
		COERBitString sameAsFirst = new COERBitString(5L,8,false)
		COERBitString second = new COERBitString(8L,8,false)
		COERBitString third = new COERBitString(5L,8,true)
		
		expect:
		first != second
		first == sameAsFirst
		first == third
		first.hashCode() != second
		first.hashCode() == sameAsFirst.hashCode()
		first.hashCode() == third.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new COERBitString(123,8,true).toString() == "COERBitString [bitString=7b, length=8]"
	}
	
	@Unroll
	def "Verify getMiminalOctetsForFixedSize returns the correct minimal number of octets #expectedlength for value #value"(){
		expect:
		COERBitString.getMiminalOctetsForFixedSize(value) == expectedlength
		where:
		value                         						      | expectedlength
		0                                						  | 0
		1                        						          | 1
		255                        							      | 1
		256                  						              | 2
		256 * 256 -1              							      | 2
		256 * 256                						          | 3
		256 * 256 * 256 -1          						      | 3
		256 * 256 * 256               							  | 4
		256 * 256 * 256  * 256L -1     							  | 4
		256 * 256 * 256  * 256L    						          | 5
		256 * 256 * 256  * 256L * 256L -1         				  | 5
		256 * 256 * 256  * 256L * 256L      				      | 6
		256 * 256 * 256  * 256L * 256L * 256L -1				  | 6
		256 * 256 * 256  * 256L * 256L * 256L         			  | 7
		256 * 256 * 256  * 256L * 256L * 256L * 256L -1           | 7
		256 * 256 * 256  * 256L * 256L * 256L * 256L              | 8
	}
	

}
