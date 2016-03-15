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
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CircularRegionSpec extends BaseStructSpec {
	
	def "Verify the constructors and getters"(){
		when:
		CircularRegion c1 = new CircularRegion(new TwoDLocation(-150,150), 1);
		then:
		c1.center.latitude == -150
		c1.center.longitude == 150
		c1.radius == 1
		when:
		new CircularRegion(new TwoDLocation(-150,150), CircularRegion.MAX_RADIUS+1);
		then:
		thrown IllegalArgumentException

	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(new CircularRegion(new TwoDLocation(-900000000,-1800000000),255)) == "ca5b170094b62e0000ff"
		serializeToHex(new CircularRegion(new TwoDLocation(-900000000,-1800000000),6666)) == "ca5b170094b62e001a0a"
		
	}
	
	def "Verify deserialization"(){
		expect:
		deserializeFromHex(new CircularRegion(),"ca5b170094b62e0000ff").center.latitude == -900000000
		deserializeFromHex(new CircularRegion(),"ca5b170094b62e0000ff").center.longitude == -1800000000
		deserializeFromHex(new CircularRegion(),"ca5b170094b62e0000ff").radius == 255
		deserializeFromHex(new CircularRegion(),"ca5b170094b62e001a0a").radius == 6666

	}

	def "Verify hashCode and equals"(){
		setup:
		def o1  = new CircularRegion(new TwoDLocation(-900000000,-1800000000),1);
		def o2  = new CircularRegion(new TwoDLocation(-900000000,-1800000000),1);
		def o3  = new CircularRegion(new TwoDLocation(-900000000,-1800000000),2);
		def o4  = new CircularRegion(new TwoDLocation(-800000000,-1800000000),1);
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
		new CircularRegion(new TwoDLocation(-800000000,-1800000000),1).toString() == "CircularRegion [center=TwoDLocation [latitude=-800000000, longitude=-1800000000], radius=1]"
	}
}
