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
import org.certificateservices.custom.c2x.its.datastructs.basic.IdentifiedRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.RegionDictionary.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class IdentifiedRegionSpec extends BaseStructSpec {
	

	IdentifiedRegion ir = new IdentifiedRegion(un_stats, 123, new IntX(new BigInteger(321)));
	
	def "Verify the constructors and getters"(){
		expect:
		ir.regionDictionary == un_stats
		ir.regionIdentifier == 123
		ir.localRegion.value.intValue() == 321
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(ir) == "01007b8141"
		
	}
	
	def "Verify deserialization"(){
		when:
		IdentifiedRegion ir1 = deserializeFromHex(new IdentifiedRegion(),"01007b8141")
		then:
		ir1.regionDictionary == un_stats
		ir1.regionIdentifier == 123
		ir1.localRegion.value.intValue() == 321

	}

	def "Verify hashCode and equals"(){
		setup:		
		def o1  = new IdentifiedRegion(un_stats, 123, new IntX(new BigInteger(321)));
		def o2  = new IdentifiedRegion(un_stats, 123, new IntX(new BigInteger(321)));
		def o3  = new IdentifiedRegion(iso_3166_1, 123, new IntX(new BigInteger(321)));
		def o4  = new IdentifiedRegion(un_stats, 124, new IntX(new BigInteger(321)));
		def o5  = new IdentifiedRegion(un_stats, 123, new IntX(new BigInteger(322)));
		expect:
		o1 == o2
		o1 != o3
		o1 != o4
		o1 != o5
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
		o1.hashCode() != o4.hashCode()
		o1.hashCode() != o5.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		ir.toString() == "IdentifiedRegion [regionDictionary=un_stats, regionIdentifier=123, localRegion=[321]]"
	}
}
