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

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all Uint classes
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfRegionAndSubregionsSpec extends BaseStructSpec {

	SequenceOfUint16 subRegions1 = new SequenceOfUint16([new Uint16(12),new Uint16(13)])
	SequenceOfUint16 subRegions2 = new SequenceOfUint16([new Uint16(16),new Uint16(17)])
	
	RegionAndSubregions rs1 = new RegionAndSubregions(5, subRegions1)
	RegionAndSubregions rs2 = new RegionAndSubregions(7, subRegions2)
	
	def "Verify that SequenceOfRegionAndSubregions is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfRegionAndSubregions(),"0102050102000c000d07010200100011")
		
		then:
		u1.getSequenceValues()[0].getRegion() == 5
		u1.getSequenceValues()[1].getRegion() == 7
		when:
		def u2 = new SequenceOfRegionAndSubregions([rs1,rs2] as RegionAndSubregions[])
		then:
		u2.getSequenceValues()[0].getRegion() == 5
		u2.getSequenceValues()[1].getRegion() == 7
		
		when:
		def u3 = new SequenceOfRegionAndSubregions([rs1,rs2])
		then:
		u3.getSequenceValuesAsList()[0].getRegion() == 5
		u3.getSequenceValuesAsList()[1].getRegion() == 7
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfRegionAndSubregions([rs1,rs2]).toString() == "SequenceOfRegionAndSubregions [[region=5, subregions=12,13],[region=7, subregions=16,17]]"
		new SequenceOfRegionAndSubregions().toString() == "SequenceOfRegionAndSubregions []"
		new SequenceOfRegionAndSubregions([rs1]).toString() == "SequenceOfRegionAndSubregions [[region=5, subregions=12,13]]"
		
	
	}
	
	


}
