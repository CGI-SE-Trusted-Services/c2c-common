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

import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryAndSubregions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.RegionAndSubregions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfRegionAndSubregions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfUint16;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint16;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CountryAndSubregions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CountryAndSubregionsSpec extends BaseStructSpec {
	
	
	RegionAndSubregions r1 = new RegionAndSubregions(5,new SequenceOfUint16([new Uint16(12),new Uint16(13)]))
	RegionAndSubregions r2 = new RegionAndSubregions(6,new SequenceOfUint16([new Uint16(14),new Uint16(15)]))
	SequenceOfRegionAndSubregions seq1 = new SequenceOfRegionAndSubregions([r1,r2])
	SequenceOfRegionAndSubregions seq2 = new SequenceOfRegionAndSubregions([])
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CountryAndSubregions cs1 = new CountryAndSubregions(new CountryOnly(5),seq1)
		then:
		serializeToHex(cs1) == "00050102050102000c000d060102000e000f"
		when:
		CountryAndSubregions cs2 = deserializeFromHex(new CountryAndSubregions(), "00050102050102000c000d060102000e000f")
		SequenceOfRegionAndSubregions seq = cs2.getRegionAndSubregions()
		then:
		cs2.getCountry().getValueAsLong() == 5
		seq == seq1
		
	}
	
	def "Verify that all fields must be set or IOException is thrown when encoding"(){
		when:
		new CountryAndSubregions(new CountryOnly(5), null)
		then:
		thrown IOException
		when:
		new CountryAndSubregions(null, seq1)
		then:
		thrown IOException
	}
	
	def "Verify toString"(){
		expect:
		new CountryAndSubregions(new CountryOnly(5),seq1).toString() == "CountryAndSubregions [country=5, region and subregions=RegionAndSubregions [region=5, subregions=12,13],RegionAndSubregions [region=6, subregions=14,15]]"
		new CountryAndSubregions(new CountryOnly(5),seq2).toString() == "CountryAndSubregions [country=5, region and subregions=]"
	}
	

}
