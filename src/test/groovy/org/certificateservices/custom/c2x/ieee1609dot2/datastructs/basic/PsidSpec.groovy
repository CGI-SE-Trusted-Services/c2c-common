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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Psid
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PsidSpec extends BaseStructSpec {

	@Unroll
	def "Verify constructors"(){
		when:
		def p1 = new Psid(255)
		
		then:
		p1.minValue == BigInteger.ZERO
		p1.maxValue == null
		p1.valueAsLong == 255
		serializeToHex(p1) == "01ff"
		
		when:
		def p2 = new Psid("ff")
		then:
		p2.minValue == BigInteger.ZERO
		p2.maxValue == null
		p2.valueAsLong == 255
		serializeToHex(p2) == "01ff"
	}
	
	
	def "Verify Psid toString"(){
		expect:
		new Psid(1000).toString() == "Psid [1000(3e8)]"
	}
	

	
	


}
