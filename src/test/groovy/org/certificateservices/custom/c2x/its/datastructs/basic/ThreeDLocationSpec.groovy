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
package org.certificateservices.custom.c2x.its.datastructs.basic


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ThreeDLocationSpec extends BaseStructSpec {
	
	def "Verify the constructors and getters"(){
		when:
		ThreeDLocation t1 = new ThreeDLocation(-150,150,150);
		then:
		t1.latitude == -150
		t1.longitude == 150
		t1.elevationInDecimeters == 150
		t1.encodedElevation == 150
		when:
		t1 = new ThreeDLocation(-150,150,70000);
		then:
		t1.elevationInDecimeters == 61439
		t1.encodedElevation == 0xEFFF
		when:
		t1 = new ThreeDLocation(-150,150,-5000);
		then:
		t1.elevationInDecimeters == -4095
		t1.encodedElevation == 0xF001
		when:
		t1 = new ThreeDLocation(-150,150,-2095);
		then:
		t1.elevationInDecimeters == -2095
		t1.encodedElevation == -2095
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(new ThreeDLocation(-900000000,-1800000000, 70000)) == "ca5b170094b62e00efff"
		serializeToHex(new ThreeDLocation(900000000,1800000000,-5000)) == "35a4e9006b49d200f001"
		serializeToHex(new ThreeDLocation(900000000,1800000000,-2095)) == "35a4e9006b49d200f7d1"
		serializeToHex(new ThreeDLocation(900000000,1800000000,150)) == "35a4e9006b49d2000096"
	}
	
	def "Verify deserialization"(){
		expect:
		deserializeFromHex(new ThreeDLocation(),"ca5b170094b62e00efff").elevationInDecimeters == 61439
		deserializeFromHex(new ThreeDLocation(),"35a4e9006b49d200f001").elevationInDecimeters == -4095
		deserializeFromHex(new ThreeDLocation(),"35a4e9006b49d200f7d1").elevationInDecimeters == -2095
		deserializeFromHex(new ThreeDLocation(),"35a4e9006b49d2000096").elevationInDecimeters == 150
		deserializeFromHex(new ThreeDLocation(),"35a4e9006b49d200f001").longitude == 1800000000
		deserializeFromHex(new ThreeDLocation(),"35a4e9006b49d200f7d1").latitude == 900000000

	}

	def "Verify hashCode and equals"(){
		setup:
		def o1  = new ThreeDLocation(-900000000,-1800000000,150);
		def o2  = new ThreeDLocation(-900000000,-1800000000,150);
		def o3  = new ThreeDLocation(-900000000,-1200000000,150);
		def o4  = new ThreeDLocation(-900000000,-1800000000,160);
		expect:
		o1 == o2
		o1 != o3
		o1 != o4
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
		o1.hashCode() != o4.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new ThreeDLocation(-900000000,-1800000000, 160).toString() == "ThreeDLocation [encodedElevation=160 (160 decimeters), latitude=-900000000, longitude=-1800000000]"
	}
}
