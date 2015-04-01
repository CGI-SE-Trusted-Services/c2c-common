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
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Time64Spec extends BaseStructSpec {
	
	def "Verify the constructors and asElapsedTime"(){
		when:
		Time64 t1 = new Time64(new Date(1416407150000L))
		then:
		t1.asElapsedTime().toString() == "154103151000000"
		when:
		t1 = new Time64(new Date(1416407150001L))
		then:
		t1.asElapsedTime().toString() == "154103151001000"
	}
	
	def "Make sure asDate converts the date correctly"(){
		when:
		Time64 t1 = new Time64(new BigInteger("154103151000000"))
		then:
		t1.asDate().time == 1416407150000L
	}
	
	def "Verify serialization"(){
		expect:
		serializeToHex(new Time64(new BigInteger("154103151000000"))) == "00008c27ef92f9c0"
		serializeToHex(new Time64(new BigInteger("1"))) == "0000000000000001"
	}
	
	def "Verify deserialization"(){
		expect:
		deserializeFromHex(new Time64(),"00008c27ef92f9c0").asDate().time == 1416407150000L
		deserializeFromHex(new Time64(),"0000000000000001").asDate().time == 1262304000000L

	}
	
	def "Verify hashCode and equals"(){
		setup:
		def t1  = new Time64(new Date(1416407150000L));
		def t2  = new Time64(new Date(1416407150000L));
		def t3  = new Time64(new Date(1416407160000L));
		expect:
		t1 == t2
		t1 != t3		
		t1.hashCode() == t2.hashCode()
		t1.hashCode() != t3.hashCode()		
	}
	
	def "Verify toString"(){
		expect:
		new Time64(new Date(1416407150000L)).toString() == "Time64 [timeStamp=Wed Nov 19 15:25:50 CET 2014 (154103151000000)]"
	}

}
