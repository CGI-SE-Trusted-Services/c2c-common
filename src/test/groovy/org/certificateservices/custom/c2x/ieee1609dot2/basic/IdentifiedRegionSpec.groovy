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
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for IdentifiedRegion
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class IdentifiedRegionSpec extends BaseStructSpec {
	
	@Shared RegionAndSubregions r1 = new RegionAndSubregions(5,new SequenceOfUint16([new Uint16(12),new Uint16(13)]))
	@Shared RegionAndSubregions r2 = new RegionAndSubregions(6,new SequenceOfUint16([new Uint16(14),new Uint16(15)]))
	@Shared SequenceOfRegionAndSubregions seq1 = new SequenceOfRegionAndSubregions([r1,r2])

	@Unroll
	def "Verify that IdentifiedRegion is correctly encoded for type #choice and value #value"(){
		when:
		def d = new IdentifiedRegion(choice, value)
		
		then:
		d.value ==  value
		serializeToHex(d) == encoding
		
		when:
		IdentifiedRegion d2 = deserializeFromHex(new IdentifiedRegion(), encoding)
		
		then:
		d.value == value
		d.getType() == choice
		
		where:
		choice                                        | encoding                                 | value
		IdentifiedRegionChoices.countryOnly           | "80000a"                                 | new CountryOnly(10)
		IdentifiedRegionChoices.countryAndRegions     | "81000501020c0d"                         | new CountryAndRegions(new CountryOnly(5),new SequenceOfUint8([new Uint8(12),new Uint8(13)]))
		IdentifiedRegionChoices.countryAndSubregions  | "8200050102050102000c000d060102000e000f" | new CountryAndSubregions(new CountryOnly(5),seq1)

		
	}
	
	def "Verify toString"(){
		expect:
		new IdentifiedRegion(IdentifiedRegionChoices.countryOnly,new CountryOnly(10)).toString() == "IdentifiedRegion [CountryOnly [10]]"
	}
	

}
