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
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlSeries
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CrlSeriesSpec extends BaseStructSpec {

	@Unroll
	def "Verify constructors"(){
		when:
		def e1 = new CrlSeries(10)
		
		then:
		serializeToHex(e1) == "000a"
		
		when:
		CrlSeries e2 = deserializeFromHex(new CrlSeries(), "000a")
		
		then:
		e2.getValueAsLong() == 10
	}
		
	
	def "Verify CrlSeries toString"(){
		expect:
		new CrlSeries(1000).toString() == "CrlSeries [1000]"
	}

}
