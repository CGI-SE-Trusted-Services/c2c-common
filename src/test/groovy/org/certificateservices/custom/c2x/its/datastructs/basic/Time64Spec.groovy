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
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.Certificate.*
/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Time64Spec extends BaseStructSpec {
	
	@Unroll
	def "Verify the constructors and asElapsedTime for certificate version #version"(){
		when:
		Time64 t1 = new Time64(version, new Date(timestamp))
		then:
		t1.asElapsedTime().toString() == expectedElapsedTime
		where:
		version                | timestamp           | expectedElapsedTime
		CERTIFICATE_VERSION_1  | 1416407150000L      | "154103151000000"
		CERTIFICATE_VERSION_1  | 1416407150001L      | "154103151001000"
		CERTIFICATE_VERSION_2  | 1227018350000L      | "154103151000000"
		CERTIFICATE_VERSION_2  | 1227018350001L      | "154103151001000"
	}
	
	@Unroll
	def "Make sure asDate converts the date correctly"(){
		when:
		Time64 t1 = new Time64(new BigInteger("154103151000000"))
		then:
		t1.asDate(version).time == timeStamp 
		where:
		version                | timeStamp
		CERTIFICATE_VERSION_1  |1416407150000L
		CERTIFICATE_VERSION_2  |1227018350000L
	}
	
	def "Verify serialization"(){
		expect:
		serializeToHex(new Time64(new BigInteger("154103151000000"))) == "00008c27ef92f9c0"
		serializeToHex(new Time64(new BigInteger("1"))) == "0000000000000001"
	}
	
	def "Verify deserialization"(){
		expect:
		deserializeFromHex(new Time64(),"00008c27ef92f9c0").asDate(CERTIFICATE_VERSION_1).time == 1416407150000L
		deserializeFromHex(new Time64(),"0000000000000001").asDate(CERTIFICATE_VERSION_1).time == 1262304000000L

	}
	
	def "Verify hashCode and equals"(){
		setup:
		def t1  = new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L));
		def t2  = new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L));
		def t3  = new Time64(CERTIFICATE_VERSION_1,new Date(1416407160000L));
		expect:
		t1 == t2
		t1 != t3		
		t1.hashCode() == t2.hashCode()
		t1.hashCode() != t3.hashCode()		
	}
	
	def "Verify toString"(){
		expect:
		new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)).toString() == "Time64 [154103151000000]"
		new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)).toString(CERTIFICATE_VERSION_1) == "Time64 [Wed Nov 19 15:25:50 CET 2014 (154103151000000)]"
		new Time64(CERTIFICATE_VERSION_2,new Date(1416407150000L)).toString(CERTIFICATE_VERSION_2) == "Time64 [Wed Nov 19 15:25:50 CET 2014 (343491953000000)]"
	}

}
