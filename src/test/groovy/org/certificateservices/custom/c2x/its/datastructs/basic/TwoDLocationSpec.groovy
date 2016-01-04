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
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class TwoDLocationSpec extends BaseStructSpec {
	
	def "Verify the constructors and getters"(){
		when:
		TwoDLocation t1 = new TwoDLocation(-150,150);
		then:
		t1.latitude == -150
		t1.longitude == 150
		when:
		new TwoDLocation(-900000001,150);
		then:
		thrown IllegalArgumentException
		when:
		new TwoDLocation(900000002,150);
		then:
		thrown IllegalArgumentException
		when:
		new TwoDLocation(-150,-1800000001);
		then:
		thrown IllegalArgumentException
		when:
		new TwoDLocation(-150,1800000002);
		then:
		thrown IllegalArgumentException
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(new TwoDLocation(-900000000,-1800000000)) == "ca5b170094b62e00"
		serializeToHex(new TwoDLocation(900000000,1800000000)) == "35a4e9006b49d200"
	}
	
	def "Verify deserialization"(){
		expect:
		deserializeFromHex(new TwoDLocation(),"ca5b170094b62e00").latitude == -900000000
		deserializeFromHex(new TwoDLocation(),"ca5b170094b62e00").longitude == -1800000000
		deserializeFromHex(new TwoDLocation(),"35a4e9006b49d200").latitude == 900000000
		deserializeFromHex(new TwoDLocation(),"35a4e9006b49d200").longitude == 1800000000

	}

	def "Verify hashCode and equals"(){
		setup:
		def o1  = new TwoDLocation(-900000000,-1800000000);
		def o2  = new TwoDLocation(-900000000,-1800000000);
		def o3  = new TwoDLocation(-900000000,-1200000000);
		def o4  = new TwoDLocation(-800000000,-1800000000);
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
		new TwoDLocation(-900000000,-1800000000).toString() == "TwoDLocation [latitude=-900000000, longitude=-1800000000]"
	}
}
