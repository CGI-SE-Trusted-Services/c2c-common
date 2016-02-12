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
import org.certificateservices.custom.c2x.its.datastructs.basic.RectangularRegion;
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
class RectangularRegionSpec extends BaseStructSpec {
	
	def "Verify the constructors and getters"(){
		when:
		RectangularRegion r1 = new RectangularRegion(new TwoDLocation(-150,150), new TwoDLocation(-250,250));
		then:
		r1.northwest.latitude == -150
		r1.northwest.longitude == 150
		r1.southeast.latitude == -250
		r1.southeast.longitude == 250
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(new RectangularRegion(new TwoDLocation(-900000000,-1800000000),new TwoDLocation(900000000,1800000000))) == "ca5b170094b62e0035a4e9006b49d200"
		
	}
	
	def "Verify deserialization"(){
		setup:
		RectangularRegion r1 = deserializeFromHex(new RectangularRegion(),"ca5b170094b62e0035a4e9006b49d200")
		expect:
		r1.northwest.latitude == -900000000
		r1.northwest.longitude == -1800000000
		r1.southeast.latitude == 900000000
		r1.southeast.longitude == 1800000000

	}

	def "Verify hashCode and equals"(){
		setup:
		def o1  = new RectangularRegion(new TwoDLocation(-150,150), new TwoDLocation(-250,250));
		def o2  = new RectangularRegion(new TwoDLocation(-150,150), new TwoDLocation(-250,250));
		def o3  = new RectangularRegion(new TwoDLocation(-151,150), new TwoDLocation(-250,250));
		def o4  = new RectangularRegion(new TwoDLocation(-150,150), new TwoDLocation(-250,251));
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
		new RectangularRegion(new TwoDLocation(-150,150), new TwoDLocation(-250,250)).toString() == "RectangularRegion [northwest=TwoDLocation [latitude=-150, longitude=150], southeast=TwoDLocation [latitude=-250, longitude=250]]"
	}
}
