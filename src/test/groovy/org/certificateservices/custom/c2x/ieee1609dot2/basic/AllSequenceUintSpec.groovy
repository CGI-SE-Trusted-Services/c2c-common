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

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all Uint classes
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class AllSequenceUintSpec extends BaseStructSpec {

	
	def "Verify that SequenceOfUint3 is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfUint3(),"01020304")
		
		then:
		u1.getSequenceValues()[0].getValueAsLong() == 3
		u1.getSequenceValues()[1].getValueAsLong() == 4
		when:
		def u2 = new SequenceOfUint3([new Uint3(3),new Uint3(4)] as Uint3[])
		then:
		u2.getSequenceValues()[0].getValueAsLong() == 3
		u2.getSequenceValues()[1].getValueAsLong() == 4
		when:
		def u3 = new SequenceOfUint3([new Uint3(3),new Uint3(4)])
		then:
		u3.getSequenceValuesAsList()[0].getValueAsLong() == 3
		u3.getSequenceValuesAsList()[1].getValueAsLong() == 4
	}
	
	def "Verify that SequenceOfUint8 is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfUint8(),"01020304")
		
		then:
		u1.getSequenceValues()[0].getValueAsLong() == 3
		u1.getSequenceValues()[1].getValueAsLong() == 4
		when:
		def u2 = new SequenceOfUint8([new Uint8(3),new Uint8(4)] as Uint8[])
		then:
		u2.getSequenceValues()[0].getValueAsLong() == 3
		u2.getSequenceValues()[1].getValueAsLong() == 4
		when:
		def u3 = new SequenceOfUint8([new Uint8(3),new Uint8(4)])
		then:
		u3.getSequenceValuesAsList()[0].getValueAsLong() == 3
		u3.getSequenceValuesAsList()[1].getValueAsLong() == 4
	}
	
	def "Verify that SequenceOfUint16 is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfUint16(),"010200030004")
		
		then:
		u1.getSequenceValues()[0].getValueAsLong() == 3
		u1.getSequenceValues()[1].getValueAsLong() == 4
		when:
		def u2 = new SequenceOfUint16([new Uint16(3),new Uint16(4)] as Uint16[])
		then:
		u2.getSequenceValues()[0].getValueAsLong() == 3
		u2.getSequenceValues()[1].getValueAsLong() == 4
		when:
		def u3 = new SequenceOfUint16([new Uint16(3),new Uint16(4)])
		then:
		u3.getSequenceValuesAsList()[0].getValueAsLong() == 3
		u3.getSequenceValuesAsList()[1].getValueAsLong() == 4
	}
	
	def "Verify toString"(){
		expect:
		new SequenceOfUint3([new Uint3(3),new Uint3(4)] as Uint3[]).toString() == "SequenceOfUint3 [3,4]"
		new SequenceOfUint3().toString() == "SequenceOfUint3 []"
		new SequenceOfUint3([new Uint3(3)] as Uint3[]).toString() == "SequenceOfUint3 [3]"
		
		new SequenceOfUint8([new Uint8(3),new Uint8(4)] as Uint8[]).toString() == "SequenceOfUint8 [3,4]"
		new SequenceOfUint8().toString() == "SequenceOfUint8 []"
		new SequenceOfUint8([new Uint8(3)] as Uint8[]).toString() == "SequenceOfUint8 [3]"
		
		new SequenceOfUint16([new Uint16(3),new Uint16(4)] as Uint16[]).toString() == "SequenceOfUint16 [3,4]"
		new SequenceOfUint16().toString() == "SequenceOfUint16 []"
		new SequenceOfUint16([new Uint16(3)] as Uint16[]).toString() == "SequenceOfUint16 [3]"
	}
	
	


}
