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
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.cert.ItsAidPriority;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ItsAidPrioritySpec extends BaseStructSpec {
	
	ItsAidPriority iap1 = new ItsAidPriority(new IntX(new BigInteger(123)), 255);
	
	def "Verify the constructors and getters"(){
		expect:
		iap1.itsAid.getValue().intValue() == 123
		iap1.maxPriority == 255

	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(iap1) == "7bff"
	}
	
	def "Verify deserialization"(){
		setup:
	    ItsAidPriority iap2 = deserializeFromHex(new ItsAidPriority(),"7bff");
		expect:
		iap2.itsAid.getValue().intValue() == 123
		iap2.maxPriority == 255

	}

	def "Verify hashCode and equals"(){
		setup:
		ItsAidPriority iap2 = new ItsAidPriority(new IntX(new BigInteger(123)), 255);
		ItsAidPriority iap3 = new ItsAidPriority(new IntX(new BigInteger(125)), 255);
		ItsAidPriority iap4 = new ItsAidPriority(new IntX(new BigInteger(123)), 123);
		expect:
		iap1 == iap2
		iap1 != iap3
		iap1 != iap4
		
		iap1.hashCode() == iap2.hashCode()
		iap1.hashCode() != iap3.hashCode()
		iap1.hashCode() != iap4.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		iap1.toString() == "ItsAidPriority [itsAid=[123], maxPriority=255]"		
	}
}

