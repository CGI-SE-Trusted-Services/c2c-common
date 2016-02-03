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

import net.time4j.PlainDate
import net.time4j.PlainTime
import net.time4j.PlainTimestamp
import net.time4j.engine.ChronoElement;
import net.time4j.scale.TimeScale;

import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Time64
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Time64Spec extends BaseStructSpec {


	Calendar cal = Calendar.getInstance();
	
	def setup(){
		cal.setTimeInMillis(0);
		cal.set(2010, 01, 02, 02, 04, 30);
	}
	
	def "Verify that Time64 converts date correctly"(){
		setup:
		Date time = cal.getTime()
		when:
		def t = new Time64(time)
		
		then:
		t.asElapsedTime().equals(new BigInteger(192157472000000))
		
		when:
		Time64 t2 = deserializeFromHex(new Time64(), serializeToHex(t))
		then:
		t2.asDate() == time
		

		when:
		def t3 = new Time64(new BigInteger(192157472000000)) // test long constructor
		then:
		t3.asElapsedTime().equals(new BigInteger(192157472000000))
		
	}
	
	def "Verify toString"(){
		expect:
		new Time64(cal.getTime()).toString() == "Time64 [timeStamp=Tue Feb 02 02:04:30 CET 2010 (192157472000000)]"
	}


}
