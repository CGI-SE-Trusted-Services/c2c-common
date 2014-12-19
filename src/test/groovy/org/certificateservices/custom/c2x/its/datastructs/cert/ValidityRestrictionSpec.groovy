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
package org.certificateservices.custom.c2x.its.datastructs.cert


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestriction;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ValidityRestrictionSpec extends BaseStructSpec {
	
	ValidityRestriction vre = new ValidityRestriction(new Time32(new Date(1416581892590L)));
	ValidityRestriction vres = new ValidityRestriction(new Time32(new Date(1416581882582L)),new Time32(new Date(1416581892590L)));
	ValidityRestriction vrsd = new ValidityRestriction(new Time32(new Date(1416581882582L)), new Duration(12, Unit.HOURS));
	ValidityRestriction vrer = new ValidityRestriction(new GeographicRegion(new CircularRegion(new TwoDLocation(-150,150), 1)));
	
	def "Verify the constructors and getters"(){
		expect:
		vre.validityRestrictionType == time_end
		vre.endValidity.asDate().time == 1416581892000L
		vre.startValidity == null
		vre.duration == null
		vre.region == null
		
		vres.validityRestrictionType == time_start_and_end
		vres.endValidity.asDate().time == 1416581892000L
		vres.startValidity.asDate().time == 1416581882000L
		vres.duration == null
		vres.region == null
		
		vrsd.validityRestrictionType == time_start_and_duration
		vrsd.endValidity == null
		vrsd.startValidity.asDate().time == 1416581882000L
		vrsd.duration.getDurationValue() == 12
		vrsd.region == null
		
		vrer.validityRestrictionType == region
		vrer.endValidity == null
		vrer.startValidity  == null
		vrer.duration == null
		vrer.region.regionType == RegionType.circle

	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(vre) == "0009321805"
		serializeToHex(vres) == "01093217fb09321805"
		serializeToHex(vrsd) == "02093217fb400c"
		serializeToHex(vrer) == "0301ffffff6a000000960001"		
	}
	
	def "Verify deserialization"(){
		setup:
	    ValidityRestriction vre2 = deserializeFromHex(new ValidityRestriction(),"0009321805");
	    ValidityRestriction vres2 = deserializeFromHex(new ValidityRestriction(),"01093217fb09321805");
	    ValidityRestriction vrsd2 = deserializeFromHex(new ValidityRestriction(),"02093217fb400c");
	    ValidityRestriction vrer2 = deserializeFromHex(new ValidityRestriction(),"0301ffffff6a000000960001");
		expect:
		vre2.validityRestrictionType == time_end
		vre2.endValidity.asDate().time == 1416581892000L
		
		vres2.validityRestrictionType == time_start_and_end
		vres2.startValidity.asDate().time == 1416581882000L
		vres2.endValidity.asDate().time == 1416581892000L
		
		vrsd2.validityRestrictionType == time_start_and_duration
		vrsd2.startValidity.asDate().time == 1416581882000L
		vrsd2.duration.getDurationValue() == 12
		
		vrer2.validityRestrictionType == region
		vrer2.region.regionType == RegionType.circle

	}

	def "Verify hashCode and equals"(){
		setup:
		ValidityRestriction vre2= new ValidityRestriction(new Time32(new Date(1416581892590L)));	
		expect:
		vre == vre2
		vre != vres
		vre != vrsd
		vre != vrer
		
		vre.hashCode() == vre2.hashCode()
		vre.hashCode() != vres.hashCode()
		vre.hashCode() != vrsd.hashCode()
		vre.hashCode() != vrer.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		vre.toString() == "ValidityRestriction [type=time_end, end_validity=Time32 [timeStamp=Fri Nov 21 15:58:12 CET 2014 (154277893)]]"
		vres.toString() == "ValidityRestriction [type=time_start_and_end, start_validity=Time32 [timeStamp=Fri Nov 21 15:58:02 CET 2014 (154277883)], end_validity=Time32 [timeStamp=Fri Nov 21 15:58:12 CET 2014 (154277893)]]"
		vrsd.toString() == "ValidityRestriction [type=time_start_and_duration, start_validity=Time32 [timeStamp=Fri Nov 21 15:58:02 CET 2014 (154277883)], duration=Duration [encodedDuration=16396 (value=12 HOURS)]]"
		vrer.toString() == "ValidityRestriction [type=region, region:=GeographicRegion [regionType=circle, circularRegion=CircularRegion [center=TwoDLocation [latitude=-150, longitude=150], radius=1]]]"
	}
}

