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

import spock.lang.Specification
import spock.lang.Unroll;

class COERIntegerSpec extends BaseStructSpec {
	
	
	
	@Unroll
	def "Verify that COERInteger with value #value returns #encoded encoded and decoded #encoded generates a #value value with minvalue #minvalue and maxvalue #maxvalue"(){
		when:
		COERInteger coerInt = new COERInteger(new BigInteger(value), (minvalue == null? null : new BigInteger(minvalue)),(maxvalue == null? null : new BigInteger(maxvalue)))
		then:
		serializeToHex(coerInt) == encoded
		
		when:
		coerInt = deserializeFromHex(new COERInteger((minvalue == null? null : new BigInteger(minvalue)),(maxvalue == null? null : new BigInteger(maxvalue))), encoded)
		then:
		coerInt.value.toString() == value
		
		where:
		encoded                                     | value                   | minvalue                | maxvalue
		"00"                                        | "0"                     | "0"                     | "255"
		"0a"          						        | "10"                    | "0"                     | "255"
		"ff"             						    | "255"                   | "0"                     | "255"
		"0000"						  			    | "0"                     | "0"                     | "65535"
		"00ff"  						    		| "255"                   | "200"                   | "65535"
		"0101"		                        	    | "257"                   | "0"                     | "65535"
		"ffff" 			                         	| "65535"                 | "0"                     | "65535"
		"00000000"  	                          	| "0"                     | "0"                     | "4294967295"
		"00000101"                                  | "257"                   | "0"                     | "4294967295"
		"ffffffff"                                  | "4294967295"            | "0"                     | "4294967295"
		"0000000000000000"                          | "0"                     | "0"                     | "18446744073709551615"
		"0000000000000101"                          | "257"                   | "0"                     | "18446744073709551615"
		"0000000100000000"                          | "4294967296"            | "0"                     | "18446744073709551615"
		"ffffffffffffffff"                          | "18446744073709551615"  | "0"                     | "18446744073709551615"
		"0100"                                      | "0"                     | "0"                     | "18446744073709551616"
		"0100"                                      | "0"                     | "0"                     | null
		"020101"                                    | "257"                   | "0"                     | null
		"08ffffffffffffffff"                        | "18446744073709551615"  | "0"                     | null
		"00"                                        | "0"                     | "-128"                  | "127"
		"80"                                        | "-128"                  | "-128"                  | "127"
		"7f"                                        | "127"                   | "-128"                  | "127"
		"007f"                                      | "127"                   | "-128"                  | "256"
		"007f"                                      | "127"                   | "-129"                  | "127"
		"8000"                                      | "-32768"                | "-32768"                | "32767"
		"7fff"                                      | "32767"                 | "-32768"                | "32767"
		"0000007f"                                  | "127"                   | "-2147483648"           | "2147483647"
		"80000000"                                  | "-2147483648"           | "-2147483648"           | "2147483647"
		"7fffffff"                                  | "2147483647"            | "-2147483648"           | "2147483647"
		"000000000000007f"                          | "127"                   | "-9223372036854775808"  | "9223372036854775807"
		"8000000000000000"                          | "-9223372036854775808"  | "-9223372036854775808"  | "9223372036854775807"
		"7fffffffffffffff"                          | "9223372036854775807"   | "-9223372036854775808"  | "9223372036854775807"
		"087fffffffffffffff"                        | "9223372036854775807"   | "-9223372036854775808"  | "9223372036854775808"
		"087fffffffffffffff"                        | "9223372036854775807"   | null                    | null
		"0180"                                      | "-128"                   | null                    | null
	}
	
	
	def "Verify that constuctor throws IllegalArgumentException if value is less than min value"(){
		when:
		new COERInteger(-4,-3,4)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify that constuctor throws IllegalArgumentException if value is more than max value"(){
		when:
		new COERInteger(5,-3,4)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify equals and hashcode"(){
		setup:
		COERInteger first = new COERInteger(4)
		COERInteger sameAsFirst = new COERInteger(4)
		COERInteger second = new COERInteger(8)
		
		expect:
		first != second
		first == sameAsFirst
		first.hashCode() != second
		first.hashCode() == sameAsFirst.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new COERInteger(123).toString() == "COERInteger [value=123]"
	}
	

}
