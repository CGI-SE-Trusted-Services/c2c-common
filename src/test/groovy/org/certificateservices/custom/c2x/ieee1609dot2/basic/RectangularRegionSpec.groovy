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
class RectangularRegionSpec extends BaseStructSpec {
	
	TwoDLocation l1 = new TwoDLocation(new Latitude(123),new Longitude(234));
	TwoDLocation l2 = new TwoDLocation(new Latitude(124),new Longitude(235));
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		RectangularRegion r1 = new RectangularRegion(l1,l2)
		then:
		serializeToHex(r1) == "0000007b000000ea0000007c000000eb"
		when:
		RectangularRegion r2 = deserializeFromHex(new RectangularRegion(), "0000007b000000ea0000007c000000eb")
		then:
		r2.getNorthWest() == l1
		r2.getSouthEast() == l2;
		
	}
	
	def "Verify that IllegalArgumentException is thrown if poistion is the same"(){
		when:
		new RectangularRegion(l1, new TwoDLocation(new Latitude(123),new Longitude(234)))
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify that all fields must be set or IllegalArgumentException is thrown when encoding"(){
		when:
		new RectangularRegion(l1, null)
		then:
		thrown IllegalArgumentException
		when:
		new RectangularRegion(null, l2)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new RectangularRegion(l1,l2).toString() == "RectangularRegion [northwest=[latitude=123, longitude=234], southeast=[latitude=124, longitude=235]]"
	}
	

}
