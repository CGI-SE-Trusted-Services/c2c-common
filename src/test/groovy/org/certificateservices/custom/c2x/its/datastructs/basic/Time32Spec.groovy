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
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.cert.Certificate.*

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Time32Spec extends BaseStructSpec {
	
	@Unroll
	def "Verify the constructors and asElapsedTime"(){
		when:
		Time32 t1 = new Time32(version,new Date(timeStamp))
		then:
		t1.asElapsedTime()== 154103151L
		where:
		version                    |     timeStamp
		CERTIFICATE_VERSION_1      | 1416407150000L
		CERTIFICATE_VERSION_2      | 1227018350000L
	}
	
	@Unroll
	def "Make sure asDate converts the date correctly"(){
		when:
		Time32 t1 = new Time32(154103151L)
		then:
		t1.asDate(version).time == timeStamp
		where:
		version                    |     timeStamp
		CERTIFICATE_VERSION_1      | 1416407150000L
		CERTIFICATE_VERSION_2      | 1227018350000L
	}
	
	def "Verify serialization"(){
		expect:
		serializeToHex(new Time32(154103151L)) == "092f6d6f"
		serializeToHex(new Time32(1L)) == "00000001"
	}
	
	def "Verify deserialization"(){
		expect:
		deserializeFromHex(new Time32(),"092f6d6f").asDate(CERTIFICATE_VERSION_1).time == 1416407150000L
		deserializeFromHex(new Time32(),"00000001").asDate(CERTIFICATE_VERSION_1).time == 1262304001000L
		deserializeFromHex(new Time32(),"00000001").asDate(CERTIFICATE_VERSION_2).time == 1072915201000L

	}

	def "Verify hashCode and equals"(){
		setup:
		def t1  = new Time32(CERTIFICATE_VERSION_1,new Date(1416407150000L));
		def t2  = new Time32(CERTIFICATE_VERSION_1,new Date(1416407150000L));
		def t3  = new Time32(CERTIFICATE_VERSION_1,new Date(1416407160000L));
		expect:
		t1 == t2
		t1 != t3
		t1.hashCode() == t2.hashCode()
		t1.hashCode() != t3.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new Time32(CERTIFICATE_VERSION_1,new Date(1416407150000L)).toString() == "Time32 [154103151]"
		new Time32(CERTIFICATE_VERSION_1,new Date(1416407150000L)).toString(CERTIFICATE_VERSION_1) == "Time32 [Wed Nov 19 15:25:50 CET 2014 (154103151)]"
		new Time32(CERTIFICATE_VERSION_2,new Date(1416407150000L)).toString(CERTIFICATE_VERSION_2) == "Time32 [Wed Nov 19 15:25:50 CET 2014 (343491953)]"
	}
}
