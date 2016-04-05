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
import org.certificateservices.custom.c2x.its.datastructs.basic.PolygonalRegion;
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
class PolygonalRegionSpec extends BaseStructSpec {
	
	List points
	
	def setup(){
		points = []
		for(int i=0;i<PolygonalRegion.MAX_POINTS;i++){
			points.add(new TwoDLocation(i, (0 -i)));
		}
	}
	
	def "Verify the constructors and getters"(){
		when:
		PolygonalRegion p1 = new PolygonalRegion(points);
		then:
		p1.points.size() == 12
		p1.points[1].latitude == 1
		p1.points[1].longitude == -1
		when:
		points.add(new TwoDLocation(13, -13));
		new PolygonalRegion(points);
		then:
		thrown IllegalArgumentException
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(new PolygonalRegion(points)) == "60000000000000000000000001ffffffff00000002fffffffe00000003fffffffd00000004fffffffc00000005fffffffb00000006fffffffa00000007fffffff900000008fffffff800000009fffffff70000000afffffff60000000bfffffff5"
		
	}
	
	def "Verify deserialization"(){
		when:
		PolygonalRegion p1 = deserializeFromHex(new PolygonalRegion(),"60000000000000000000000001ffffffff00000002fffffffe00000003fffffffd00000004fffffffc00000005fffffffb00000006fffffffa00000007fffffff900000008fffffff800000009fffffff70000000afffffff60000000bfffffff5")
		then:
		p1.points.size() == 12
		for(int i=0;i<12;i++){
			assert p1.points[i].latitude == i
			assert p1.points[i].longitude == (0-i)
		}

	}

	def "Verify hashCode and equals"(){
		setup:
		def points2 = []
		for(int i=0;i<PolygonalRegion.MAX_POINTS;i++){
			points2.add(new TwoDLocation(i, (0 -i)));
		}
		def points3 = []
		for(int i=0;i<PolygonalRegion.MAX_POINTS;i++){
			points3.add(new TwoDLocation(i, (i)));
		}
		
		def o1  = new PolygonalRegion(points);
		def o2  = new PolygonalRegion(points2);
		def o3  = new PolygonalRegion(points3);
		expect:
		o1 == o2
		o1 != o3
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new PolygonalRegion(points).toString() == "PolygonalRegion [[latitude=0, longitude=0], [latitude=1, longitude=-1], [latitude=2, longitude=-2], [latitude=3, longitude=-3], [latitude=4, longitude=-4], [latitude=5, longitude=-5], [latitude=6, longitude=-6], [latitude=7, longitude=-7], [latitude=8, longitude=-8], [latitude=9, longitude=-9], [latitude=10, longitude=-10], [latitude=11, longitude=-11]]"
	}
}
