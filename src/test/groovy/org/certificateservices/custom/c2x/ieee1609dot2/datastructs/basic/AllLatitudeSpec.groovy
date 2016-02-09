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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.KnownLatitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.NinetyDegreeInt;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.UnknownLatitude;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all Latitude specifications
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class AllLatitudeSpec extends BaseStructSpec {

	
	def "Verify that Latitude constructors sets the correct min and max values."(){
		when:
		def d1 = new Latitude()
		def d2 = new Latitude(123L)
		then:
		d1.minValue.longValue() == NinetyDegreeInt.MIN
		d1.maxValue.longValue() == NinetyDegreeInt.UNKNOWN
		
		d2.minValue.longValue() == NinetyDegreeInt.MIN
		d2.maxValue.longValue() == NinetyDegreeInt.UNKNOWN
		d2.value.longValue() == 123L
		
	}
	
	def "Verify Latitude toString"(){
		expect:
		new Latitude(1000).toString() == "Latitude [1000]"
		new Latitude(NinetyDegreeInt.UNKNOWN).toString() == "Latitude [UNKNOWN]"
	}

	
	def "Verify that KnownLatitude constructors sets the correct min and max values."(){
		when:
		def d1 = new KnownLatitude()
		def d2 = new KnownLatitude(123L)
		then:
		d1.minValue.longValue() == NinetyDegreeInt.MIN
		d1.maxValue.longValue() == NinetyDegreeInt.MAX
		
		d2.minValue.longValue() == NinetyDegreeInt.MIN
		d2.maxValue.longValue() == NinetyDegreeInt.MAX
		d2.value.longValue() == 123L
		
	}
	
	def "Verify KnownLatitude toString"(){
		expect:
		new KnownLatitude(1000).toString() == "KnownLatitude [1000]"
	}
	
	def "Verify that UnknownLatitude constructors sets the correct min and max values."(){
		when:
		def d1 = new UnknownLatitude()
		then:
		d1.minValue.longValue() == NinetyDegreeInt.MIN
		d1.maxValue.longValue() == NinetyDegreeInt.UNKNOWN
		d1.value.longValue() == NinetyDegreeInt.UNKNOWN
	}
	
	def "Verify UnknownLatitude toString"(){
		expect:
		new UnknownLatitude().toString() == "UnknownLatitude [UNKNOWN]"
	}
	

	
	
	def "Verify that NinetyDegreeInt constructors sets the correct min and max values."(){
		when:
		def d1 = new NinetyDegreeInt()
		def d2 = new NinetyDegreeInt(123L)
		then:
		d1.minValue.longValue() == NinetyDegreeInt.MIN
		d1.maxValue.longValue() == NinetyDegreeInt.UNKNOWN
		
		d2.minValue.longValue() == NinetyDegreeInt.MIN
		d2.maxValue.longValue() == NinetyDegreeInt.UNKNOWN
		d2.value.longValue() == 123L
		
	}
	
	
	def "Verify NinetyDegreeInt toString"(){
		expect:
		new NinetyDegreeInt(1000).toString() == "NinetyDegreeInt [1000]"
		new NinetyDegreeInt(NinetyDegreeInt.UNKNOWN).toString() == "NinetyDegreeInt [UNKNOWN]"
	}
	

}
