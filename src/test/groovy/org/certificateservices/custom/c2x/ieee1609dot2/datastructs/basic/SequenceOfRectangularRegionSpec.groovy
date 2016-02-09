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

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.RectangularRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfRectangularRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.TwoDLocation;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfRectangularRegion class
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfRectangularRegionSpec extends BaseStructSpec {

	RectangularRegion rr1 = new RectangularRegion(new TwoDLocation(new Latitude(123),new Longitude(234)),new TwoDLocation(new Latitude(2123),new Longitude(2234)))
	RectangularRegion rr2 = new RectangularRegion(new TwoDLocation(new Latitude(3123),new Longitude(3234)),new TwoDLocation(new Latitude(4123),new Longitude(4234)))
	
	
	def "Verify that SequenceOfRectangularRegion is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfRectangularRegion(),"01020000007b000000ea0000084b000008ba00000c3300000ca20000101b0000108a")
		then:
		u1.getSequenceValues()[0] == rr1
		u1.getSequenceValues()[1] == rr2
		when:
		def u2 = new SequenceOfRectangularRegion([rr1,rr2] as RectangularRegion[])
		then:
		u2.getSequenceValues()[0] == rr1
		u2.getSequenceValues()[1] == rr2
		
		when:
		def u3 = new SequenceOfRectangularRegion([rr1,rr2])
		then:
		u2.getSequenceValues()[0] == rr1
		u2.getSequenceValues()[1] == rr2
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfRectangularRegion([rr1,rr2]).toString() == "SequenceOfRectangularRegion [[northwest=[latitude=123, longitude=234], southeast=[latitude=2123, longitude=2234]],[northwest=[latitude=3123, longitude=3234], southeast=[latitude=4123, longitude=4234]]]"
		new SequenceOfRectangularRegion().toString() == "SequenceOfRectangularRegion []"
		new SequenceOfRectangularRegion([rr1]).toString() == "SequenceOfRectangularRegion [[northwest=[latitude=123, longitude=234], southeast=[latitude=2123, longitude=2234]]]"
		
	
	}
	
	


}
