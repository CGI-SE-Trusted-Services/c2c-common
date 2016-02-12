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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Elevation;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ThreeDLocation;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for ThreeDLocation
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ThreeDLocationSpec extends BaseStructSpec {

	Latitude lat = new Latitude(123L)
	Latitude lat_u = new Latitude(Latitude.UNKNOWN)
	
	Longitude lon = new Longitude(245L)
	Longitude lon_u = new Longitude(Longitude.UNKNOWN)
	
	Elevation e = new Elevation(10)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		ThreeDLocation td1 = new ThreeDLocation(lat,lon,e)
		then:
		serializeToHex(td1) == "0000007b000000f5000a"
		when:
		ThreeDLocation td2 = deserializeFromHex(new ThreeDLocation(), "0000007b000000f5000a")
		then:
		td2.getLatitude().getValueAsLong() == 123L
		td2.getLongitude().getValueAsLong() == 245L
		td2.getElevation().getValueAsLong() == 10
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new ThreeDLocation(lat,null,e)
		then:
		thrown IllegalArgumentException
		when:
		new ThreeDLocation(lat,lon,null)
		then:
		thrown IllegalArgumentException
		when:
		new ThreeDLocation(null,lon,e)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new ThreeDLocation(lat,lon,e).toString() == "ThreeDLocation [latitude=123, longitude=245, elevation=10]"
		new ThreeDLocation(lat_u,lon_u,e).toString() == "ThreeDLocation [latitude=UNKNOWN, longitude=UNKNOWN, elevation=10]"
	}
	

}
