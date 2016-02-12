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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryAndRegions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfUint8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for RegionAndSubregions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CountryAndRegionsSpec extends BaseStructSpec {
	
	SequenceOfUint8 regions = new SequenceOfUint8([new Uint8(12),new Uint8(13)])
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CountryAndRegions r1 = new CountryAndRegions(new CountryOnly(5),regions)
		then:
		serializeToHex(r1) == "000501020c0d"
		when:
		CountryAndRegions r2 = deserializeFromHex(new CountryAndRegions(), "000501020c0d")
		then:
		r2.getCountryOnly().getValueAsLong() == 5
		r2.getRegions() == regions;
		
	}
	
	def "Verify that all fields must be set or IllegalArgumentException is thrown when encoding"(){
		when:
		new CountryAndRegions(new CountryOnly(5), null)
		then:
		thrown IllegalArgumentException
		when:
		serializeToHex(new CountryAndRegions(null, regions))
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new CountryAndRegions(new CountryOnly(5),regions).toString() == "CountryAndRegions [countryOnly=5, regions=12,13]"
	}
	

}
