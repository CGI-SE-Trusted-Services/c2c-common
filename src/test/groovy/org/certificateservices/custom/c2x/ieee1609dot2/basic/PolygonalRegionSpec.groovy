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

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all Uint classes
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PolygonalRegionSpec extends BaseStructSpec {

	TwoDLocation l1 = new TwoDLocation(new Latitude(123),new Longitude(234));
	TwoDLocation l2 = new TwoDLocation(new Latitude(124),new Longitude(235));
	TwoDLocation l3 = new TwoDLocation(new Latitude(125),new Longitude(236));
	TwoDLocation l4 = new TwoDLocation(new Latitude(126),new Longitude(237));

	

	def "Verify that PolygonalRegion is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new PolygonalRegion(),"01040000007b000000ea0000007c000000eb0000007d000000ec0000007e000000ed")
		then:
		u1.getSequenceValues()[0].getLatitude().getValueAsLong() == 123
		u1.getSequenceValues()[0].getLongitude().getValueAsLong() == 234
		u1.getSequenceValues()[1].getLatitude().getValueAsLong() == 124
		u1.getSequenceValues()[1].getLongitude().getValueAsLong() == 235
		u1.getSequenceValues()[2].getLatitude().getValueAsLong() == 125
		u1.getSequenceValues()[2].getLongitude().getValueAsLong() == 236
		u1.getSequenceValues()[3].getLatitude().getValueAsLong() == 126
		u1.getSequenceValues()[3].getLongitude().getValueAsLong() == 237
		when:
		def u2 = new PolygonalRegion([l1,l2,l3,l4] as TwoDLocation[])
		then:
		u2.getSequenceValues()[0].getLatitude().getValueAsLong() == 123
		u2.getSequenceValues()[0].getLongitude().getValueAsLong() == 234
		u2.getSequenceValues()[1].getLatitude().getValueAsLong() == 124
		u2.getSequenceValues()[1].getLongitude().getValueAsLong() == 235
		u2.getSequenceValues()[2].getLatitude().getValueAsLong() == 125
		u2.getSequenceValues()[2].getLongitude().getValueAsLong() == 236
		u2.getSequenceValues()[3].getLatitude().getValueAsLong() == 126
		u2.getSequenceValues()[3].getLongitude().getValueAsLong() == 237
		
		when:
		def u3 = new PolygonalRegion([l1,l2,l3,l4])
		then:
		u2.getSequenceValues().length == 4
	}
	
	def "Verify that plygonalRegion of length less than 3 throws IllegalArgumentException"(){
		when:
		new PolygonalRegion([l1,l2])
		then:
		thrown IllegalArgumentException
		when:
		new PolygonalRegion([l1])
		then:
		thrown IllegalArgumentException
		when:
		new PolygonalRegion([])
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new PolygonalRegion([l1,l2,l3,l4]).toString() == "PolygonalRegion [[latitude=123, longitude=234],[latitude=124, longitude=235],[latitude=125, longitude=236],[latitude=126, longitude=237]]"
	}
	
	


}
