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
package org.certificateservices.custom.c2x.ieee1609dot2.basic

import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all Uint classes
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class AllUintSpec extends Specification {

	
	def "Verify that Uint3 has min value 0 and 7"(){
		when:
		def u1 = new Uint3()
		def u2 = new Uint3(7)
		then:
		u1.minValue.intValue() == 0
		u2.minValue.intValue() == 0
		
		u1.maxValue.intValue() == 7
		u2.maxValue.intValue() == 7
		
		u2.valueAsLong == 7
	}
	
	def "Verify that Uint8 has min value 0 and 255"(){
		when:
		def u1 = new Uint8()
		def u2 = new Uint8(255)
		then:
		u1.minValue.intValue() == 0
		u2.minValue.intValue() == 0
		
		u1.maxValue.intValue() == 255
		u2.maxValue.intValue() == 255
		
		u2.valueAsLong == 255
	}
	
	def "Verify that Uint16 has min value 0 and 65535"(){
		when:
		def u1 = new Uint16()
		def u2 = new Uint16(65535)
		then:
		u1.minValue.intValue() == 0
		u2.minValue.intValue() == 0
		
		u1.maxValue.intValue() == 65535
		u2.maxValue.intValue() == 65535
		
		u2.valueAsLong == 65535
	}
	
	def "Verify that Uint32 has min value 0 and 4294967295"(){
		when:
		def u1 = new Uint32()
		def u2 = new Uint32(4294967295L)
		then:
		u1.minValue.intValue() == 0
		u2.minValue.intValue() == 0
		
		u1.maxValue.longValue() == 4294967295L
		u2.maxValue.longValue() == 4294967295L
		
		u2.valueAsLong == 4294967295L
	}
	
	def "Verify that Uint64 has min value 0 and 18446744073709551615"(){
		when:
		def expectedMax = new BigInteger("18446744073709551615")
		def u1 = new Uint64()
		def u2 = new Uint64(expectedMax)
		then:
		u1.minValue.intValue() == 0
		u2.minValue.intValue() == 0
		
		u1.maxValue.equals(expectedMax)
		u2.maxValue.equals(expectedMax)
		
		u2.value.equals(expectedMax)
	}
	
	def "Verify toString"(){
		expect:
		new Uint3(7).toString() == "Uint3 [7]"
		new Uint8(255).toString() == "Uint8 [255]"
		new Uint16(65535).toString() == "Uint16 [65535]"
		new Uint32(4294967295L).toString() == "Uint32 [4294967295]"
		new Uint64(new BigInteger("18446744073709551615")).toString() == "Uint64 [18446744073709551615]"
	}
}
