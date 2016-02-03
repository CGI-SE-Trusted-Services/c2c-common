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

import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for UncompressedEccPoint
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class UncompressedEccPointSpec extends BaseStructSpec {

	byte[] x = new BigInteger(123).toByteArray()
	byte[] y = new BigInteger(245).toByteArray()
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		UncompressedEccPoint p1 = new UncompressedEccPoint(x,y)
		then:
		serializeToHex(p1) == "000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		UncompressedEccPoint p2 = deserializeFromHex(new UncompressedEccPoint(), "000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		p2.getX().length == 32
		p2.getY().length == 32
		new BigInteger(1,p2.getX()).intValue() == 123
		new BigInteger(1,p2.getY()).intValue() == 245
		
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		serializeToHex(new UncompressedEccPoint(x,null))
		then:
		thrown IOException
		when:
		serializeToHex(new UncompressedEccPoint(null,y))
		then:
		thrown IOException
	} 
	

	
	def "Verify toString"(){
		expect:
		new UncompressedEccPoint(x,y).toString() == "UncompressedEccPoint [x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000f5]"
	}
	

}
