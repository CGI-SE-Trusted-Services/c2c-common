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
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.GeographicRegion.GeographicRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for GeographicRegion
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class GeographicRegionSpec extends BaseStructSpec {
	
	@Shared TwoDLocation l1 = new TwoDLocation(new Latitude(123),new Longitude(234));
	@Shared TwoDLocation l2 = new TwoDLocation(new Latitude(124),new Longitude(235));
	@Shared TwoDLocation l3 = new TwoDLocation(new Latitude(125),new Longitude(236));
	@Shared TwoDLocation l4 = new TwoDLocation(new Latitude(126),new Longitude(237));
	
	@Shared CircularRegion cr1 
	@Shared SequenceOfRectangularRegion srr1
	@Shared PolygonalRegion pr1
	@Shared SequenceOfIdentifiedRegion sir1
	
	def setupSpec(){
		cr1 = new CircularRegion(l1, 5)
		srr1 = new SequenceOfRectangularRegion([new RectangularRegion(l1,l2), new RectangularRegion(l2,l3)])
		pr1 = new PolygonalRegion([l1,l2,l3])
		sir1 = new SequenceOfIdentifiedRegion([new IdentifiedRegion(IdentifiedRegionChoices.countryOnly, new CountryOnly(10))])
	}
	
	
	@Unroll
	def "Verify that GeographicRegion is correctly encoded for type #choice and value #value"(){
		when:
		def d = new GeographicRegion(choice, value)
		
		then:
		d.value ==  value
		serializeToHex(d) == encoding
		
		when:
		GeographicRegion d2 = deserializeFromHex(new GeographicRegion(), encoding)
		
		then:
		d.value == value
		d.getType() == choice
		
		where:
		choice                                           | value   |  encoding
		GeographicRegionChoices.circularRegion           | cr1     | "800000007b000000ea0005"  
		GeographicRegionChoices.rectangularRegion        | srr1    | "8101020000007b000000ea0000007c000000eb0000007c000000eb0000007d000000ec"   
		GeographicRegionChoices.polygonalRegion          | pr1     | "8201030000007b000000ea0000007c000000eb0000007d000000ec" 
		GeographicRegionChoices.identifiedRegion         | sir1    | "83010180000a" 

		
	}
	
	def "Verify toString"(){
		expect:
		new GeographicRegion(GeographicRegionChoices.circularRegion,cr1).toString() == "GeographicRegion [CircularRegion [center=[latitude=123, longitude=234], radius=5]]"
	}
	

}
