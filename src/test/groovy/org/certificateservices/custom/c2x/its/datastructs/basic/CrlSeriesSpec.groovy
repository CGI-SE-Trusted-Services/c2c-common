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
import org.certificateservices.custom.c2x.its.datastructs.basic.CrlSeries;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CrlSeriesSpec extends BaseStructSpec {
	
	
	
	def "Verify constructors and getters and setters"(){
		when:
		CrlSeries s = new CrlSeries(1);
		then:
		s.value == 1
		
	}

	byte[] testValue = Hex.decode("FFFFFFFF");

	def "Verify serialization of CrlSeries"(){
		when: 
		String result = serializeToHex(new CrlSeries(0xFFFFFFFF));
		then:
		result.length() /2 == 4;
		result == "ffffffff"
		when:
		result = serializeToHex(new CrlSeries(1));
		then:
		result.length() /2 == 4;
		result == "00000001"
	}
	
	def "Verify deserialization of CrlSeries"(){
		when:                                        
		CrlSeries result = deserializeFromHex(new CrlSeries(), "FFFFFFFF");
		then:
		result.value == 0xffffffff
		when:
		result = deserializeFromHex(new CrlSeries(), "00000001");
		then:
		result.value == 1
	}
	
	
	def "Verify hashCode and equals"(){
		setup:
		def o1  = new CrlSeries(1);
		def o2  = new CrlSeries(1);
		def o3  = new CrlSeries(2);
		expect:
		o1 == o2
		o1 != o3
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		 new CrlSeries(2).toString() == "CrlSeries [2]"
	}

	

}
