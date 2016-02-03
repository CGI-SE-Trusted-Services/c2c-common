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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Elevation
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class AllElevationSpec extends BaseStructSpec {

	@Unroll
	def "Verify constructors"(){
		when:
		def e1 = new Elevation(-1)
		
		then:
		serializeToHex(e1) == "ffff"
		
		when:
		Elevation e2 = deserializeFromHex(new Elevation(), "ffff")
		
		then:
		e2.getElevationInDecimeters() == -1
	}
	
	
	def "Verify Elevation toString"(){
		expect:
		new Elevation(1000).toString() == "Elevation [1000(3e8)]"
	}
	
	@Unroll
	def "Verify that ElevInt encodes #value to #encoding and decodes back correctly"(){
		when:
		def e1 = new ElevInt(value)
		
		then:
		serializeToHex(e1) == encoding
		e1.getEncodedElevation() == new BigInteger(1,Hex.decode(encoding)).toInteger()
		
		when:
		ElevInt e2 = deserializeFromHex(new ElevInt(), encoding)
		
		then:
		e2.getElevationInDecimeters() == expectedValue
		
		where:
		value            | encoding    | expectedValue
		0                | "0000"      | 0
		-1               | "ffff"      | -1
		-5000            | "f001"      | -4095
		1000             | "03e8"      | 1000
		61439            | "efff"      | 61439
		61440            | "efff"      | 61439
		99999            | "efff"      | 61439
		
	}
	
	
	def "Verify ElevInt toString"(){
		expect:
		new ElevInt(1000).toString() == "ElevInt [1000(3e8)]"
	}

}
