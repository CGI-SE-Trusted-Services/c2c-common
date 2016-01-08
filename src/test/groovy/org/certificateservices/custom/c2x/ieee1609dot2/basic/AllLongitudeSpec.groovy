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
 * Test for all longitude specifications.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class AllLongitudeSpec extends BaseStructSpec {

	
	def "Verify that Longitude constructors sets the correct min and max values."(){
		when:
		def d1 = new Longitude()
		def d2 = new Longitude(123L)
		then:
		d1.minValue.longValue() == OneEightyDegreeInt.MIN
		d1.maxValue.longValue() == OneEightyDegreeInt.UNKNOWN
		
		d2.minValue.longValue() == OneEightyDegreeInt.MIN
		d2.maxValue.longValue() == OneEightyDegreeInt.UNKNOWN
		d2.value.longValue() == 123L
		
	}
	
	def "Verify Longitude toString"(){
		expect:
		new Longitude(1000).toString() == "Longitude [1000]"
		new Longitude(OneEightyDegreeInt.UNKNOWN).toString() == "Longitude [UNKNOWN]"
	}

	
	def "Verify that KnownLongitude constructors sets the correct min and max values."(){
		when:
		def d1 = new KnownLongitude()
		def d2 = new KnownLongitude(123L)
		then:
		d1.minValue.longValue() == OneEightyDegreeInt.MIN
		d1.maxValue.longValue() == OneEightyDegreeInt.MAX
		
		d2.minValue.longValue() == OneEightyDegreeInt.MIN
		d2.maxValue.longValue() == OneEightyDegreeInt.MAX
		d2.value.longValue() == 123L
		
	}
	
	def "Verify KnownLongitude toString"(){
		expect:
		new KnownLongitude(1000).toString() == "KnownLongitude [1000]"
	}
	
	def "Verify that UnknownLongitude constructors sets the correct min and max values."(){
		when:
		def d1 = new UnknownLongitude()
		then:
		d1.minValue.longValue() == OneEightyDegreeInt.MIN
		d1.maxValue.longValue() == OneEightyDegreeInt.UNKNOWN
		d1.value.longValue() == OneEightyDegreeInt.UNKNOWN
	}
	
	def "Verify UnknownLongitude toString"(){
		expect:
		new UnknownLongitude().toString() == "UnknownLongitude [UNKNOWN]"
	}
	

	
	
	def "Verify that OneEightyDegreeInt constructors sets the correct min and max values."(){
		when:
		def d1 = new OneEightyDegreeInt()
		def d2 = new OneEightyDegreeInt(123L)
		then:
		d1.minValue.longValue() == OneEightyDegreeInt.MIN
		d1.maxValue.longValue() == OneEightyDegreeInt.UNKNOWN
		
		d2.minValue.longValue() == OneEightyDegreeInt.MIN
		d2.maxValue.longValue() == OneEightyDegreeInt.UNKNOWN
		d2.value.longValue() == 123L
		
	}
	
	
	def "Verify OneEightyDegreeInt toString"(){
		expect:
		new OneEightyDegreeInt(1000).toString() == "OneEightyDegreeInt [1000]"
		new OneEightyDegreeInt(OneEightyDegreeInt.UNKNOWN).toString() == "OneEightyDegreeInt [UNKNOWN]"
	}
	

}
