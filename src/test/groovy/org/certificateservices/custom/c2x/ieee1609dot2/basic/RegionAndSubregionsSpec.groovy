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

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for RegionAndSubregions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class RegionAndSubregionsSpec extends BaseStructSpec {
	
	SequenceOfUint16 subRegions = new SequenceOfUint16([new Uint16(12),new Uint16(13)])
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		RegionAndSubregions r1 = new RegionAndSubregions(5,subRegions)
		then:
		serializeToHex(r1) == "050102000c000d"
		when:
		RegionAndSubregions r2 = deserializeFromHex(new RegionAndSubregions(), "050102000c000d")
		then:
		r2.getRegion() == 5
		r2.getSubRegions() == subRegions;
		
	}
	
	def "Verify that all fields must be set or IllegalArgumentException is thrown when encoding"(){
		when:
		new RegionAndSubregions(1, null)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new RegionAndSubregions(5,subRegions).toString() == "RegionAndSubregions [region=5, subregions=12,13]"
	}
	

}
