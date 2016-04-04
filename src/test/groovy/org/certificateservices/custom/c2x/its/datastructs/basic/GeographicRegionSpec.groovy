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
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.IdentifiedRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PolygonalRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.RectangularRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionDictionary;
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.RegionType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class GeographicRegionSpec extends BaseStructSpec {
	
	GeographicRegion grn = new GeographicRegion();
	GeographicRegion grc = new GeographicRegion(new CircularRegion(new TwoDLocation(-150,150), 1));
	GeographicRegion grr = new GeographicRegion([new RectangularRegion(new TwoDLocation(-150,150), new TwoDLocation(-250,250)), new RectangularRegion(new TwoDLocation(-100,100), new TwoDLocation(-200,200))]);
	GeographicRegion grp = new GeographicRegion(new PolygonalRegion([new TwoDLocation(1, -1),new TwoDLocation(2, -2)]));
	GeographicRegion gri = new GeographicRegion(new IdentifiedRegion(RegionDictionary.un_stats, 123, new IntX(new BigInteger(321))));
	
	def "Verify the constructors and getters"(){
		expect:
		grn.regionType == none
		grc.regionType == circle
		grc.circularRegion != null
		grr.regionType == rectangle
		grr.rectangularRegions.size() == 2
		grp.regionType == polygon
		grp.polygonalRegion != null
		gri.regionType == id
		gri.identifiedRegion != null
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(grn) == "00"
		serializeToHex(grc) == "01ffffff6a000000960001"
		serializeToHex(grr) == "0220ffffff6a00000096ffffff06000000faffffff9c00000064ffffff38000000c8"
		serializeToHex(grp) == "031000000001ffffffff00000002fffffffe"
		serializeToHex(gri) == "0401007b8141"		
	}
	
	def "Verify deserialization"(){
		setup:
	    GeographicRegion grn2 = deserializeFromHex(new GeographicRegion(),"00");
	    GeographicRegion grc2 = deserializeFromHex(new GeographicRegion(),"01ffffff6a000000960001");
	    GeographicRegion grr2 = deserializeFromHex(new GeographicRegion(),"0220ffffff6a00000096ffffff06000000faffffff9c00000064ffffff38000000c8");
	    GeographicRegion grp2 = deserializeFromHex(new GeographicRegion(),"030200000001ffffffff00000002fffffffe");
	    GeographicRegion gri2 = deserializeFromHex(new GeographicRegion(),"0401007b8141");
		expect:
		grn2.regionType == none
		grc2.regionType == circle
		grc2.circularRegion != null
		grr2.regionType == rectangle
		grr2.rectangularRegions.size() == 2
		grp2.regionType == polygon
		grp2.polygonalRegion != null
		gri2.regionType == id
		gri2.identifiedRegion != null

	}

	def "Verify hashCode and equals"(){
		setup:
		GeographicRegion grc2 = new GeographicRegion(new CircularRegion(new TwoDLocation(-150,150), 1));		
		expect:
		grc == grc
		grc != grn
		grc != grr
		grc != grp
		grc != gri
		
		grc.hashCode() == grc.hashCode()
		grc.hashCode() != grn.hashCode()
		grc.hashCode() != grr.hashCode()
		grc.hashCode() != grp.hashCode()
		grc.hashCode() != gri.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		grn.toString() == "GeographicRegion [regionType=none]"
		grc.toString() == "GeographicRegion [regionType=circle, circularRegion=[center=[latitude=-150, longitude=150], radius=1]]"
		grr.toString() == "GeographicRegion [regionType=rectangle, rectangularRegions=[northwest=[latitude=-150, longitude=150], southeast=[latitude=-250, longitude=250]], [northwest=[latitude=-100, longitude=100], southeast=[latitude=-200, longitude=200]]]"
		grp.toString() == "GeographicRegion [regionType=polygon, polygonalRegion=[[latitude=1, longitude=-1], [latitude=2, longitude=-2]]]"
		gri.toString() == "GeographicRegion [regionType=id, identifiedRegion=[regionDictionary=un_stats, regionIdentifier=123, localRegion=[321]]]"
	}
}

