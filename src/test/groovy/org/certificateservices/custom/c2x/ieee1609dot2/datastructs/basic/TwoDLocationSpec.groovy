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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.TwoDLocation;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for ThreeDLocation
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class TwoDLocationSpec extends BaseStructSpec {

	Latitude lat = new Latitude(123L)
	Latitude lat_u = new Latitude(Latitude.UNKNOWN)
	
	Longitude lon = new Longitude(245L)
	Longitude lon_u = new Longitude(Longitude.UNKNOWN)
	
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		TwoDLocation td1 = new TwoDLocation(lat,lon)
		then:
		serializeToHex(td1) == "0000007b000000f5"
		when:
		TwoDLocation td2 = deserializeFromHex(new TwoDLocation(), "0000007b000000f5")
		then:
		td2.getLatitude().getValueAsLong() == 123L
		td2.getLongitude().getValueAsLong() == 245L
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new TwoDLocation(lat,null)
		then:
		thrown IllegalArgumentException
		when:
		new TwoDLocation(null,lon)
		then:
		thrown IllegalArgumentException
	} 
	
	def "Verify that IllegalArgumentException is thrown if UNKNOWN is used as latitude or longitude"(){
		when:
		new TwoDLocation(lat,lon_u)
		then:
		thrown IllegalArgumentException
		when:
		new TwoDLocation(lat_u,lon)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new TwoDLocation(lat,lon).toString() == "TwoDLocation [latitude=123, longitude=245]"
	}
	

}
