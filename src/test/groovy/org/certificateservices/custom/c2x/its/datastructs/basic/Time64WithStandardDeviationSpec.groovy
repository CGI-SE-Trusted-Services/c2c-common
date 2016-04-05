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
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64WithStandardDeviation;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.Certificate.*

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Time64WithStandardDeviationSpec extends BaseStructSpec {
	
	def "Verify the constructors and getters"(){
		when:
		Time64WithStandardDeviation t1 = new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)),1);
		then:
		t1.getTime().asElapsedTime().toString() == "154103151000000"
		t1.getLogStdDev() == 1
		
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(new Time64WithStandardDeviation(new Time64(new BigInteger("154103151000000")),1)) == "00008c27ef92f9c001"
		
	}
	
	def "Verify deserialization"(){
		when:
		def t = deserializeFromHex(new Time64WithStandardDeviation(),"00008c27ef92f9c001")
		then:
		t.getTime().asDate(CERTIFICATE_VERSION_1).time == 1416407150000L
		t.getLogStdDev() == 1
	}
	
	def "Verify hashCode and equals"(){
		setup:
		def t1  = new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)),1)
		def t2  = new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)),1)
		def t3  = new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)),2)
		def t4  = new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_1,new Date(1416407160000L)),1)
		expect:
		t1 == t2
		t1 != t3
		t1 != t4
		t1.hashCode() == t2.hashCode()
		t1.hashCode() != t3.hashCode()
		t1.hashCode() != t4.hashCode()		
	}
	
	def "Verify toString"(){
		expect:
		new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)),1).toString() == "Time64WithStandardDeviation [time=[154103151000000], logStdDev=1]"
		new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_1,new Date(1416407150000L)),1).toString(CERTIFICATE_VERSION_1) == "Time64WithStandardDeviation [time=[Wed Nov 19 15:25:50 CET 2014 (154103151000000)], logStdDev=1]"
		new Time64WithStandardDeviation(new Time64(CERTIFICATE_VERSION_2,new Date(1416407150000L)),1).toString(CERTIFICATE_VERSION_2) == "Time64WithStandardDeviation [time=[Wed Nov 19 15:25:50 CET 2014 (343491953000000)], logStdDev=1]"
	}

}
