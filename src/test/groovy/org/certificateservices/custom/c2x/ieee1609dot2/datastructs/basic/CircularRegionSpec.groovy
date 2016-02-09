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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CircularRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.TwoDLocation;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CircularRegion
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CircularRegionSpec extends BaseStructSpec {

	TwoDLocation l1 = new TwoDLocation(new Latitude(123),new Longitude(234));
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CircularRegion cr1 = new CircularRegion(l1,5)
		then:
		serializeToHex(cr1) == "0000007b000000ea0005"
		when:
		CircularRegion cr2 = deserializeFromHex(new CircularRegion(), "0000007b000000ea0005")
		then:
		
		cr2.getCenter() == l1;
		cr2.getRadius() == 5
		
	}
	
	def "Verify that all fields must be set or IllegalArgumentException is thrown when encoding"(){
		when:
		new CircularRegion(null, 1)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new CircularRegion(l1,5).toString() == "CircularRegion [center=[latitude=123, longitude=234], radius=5]"
	}

}
