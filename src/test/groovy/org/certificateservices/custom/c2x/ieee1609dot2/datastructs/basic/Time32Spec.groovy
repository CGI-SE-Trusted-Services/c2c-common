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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import net.time4j.PlainDate
import net.time4j.PlainTime
import net.time4j.PlainTimestamp
import net.time4j.engine.ChronoElement;
import net.time4j.scale.TimeScale;

import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Time32
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Time32Spec extends BaseStructSpec {


	Calendar cal = Calendar.getInstance();
	
	def setup(){
		cal.setTimeInMillis(0);
		cal.set(2010, 01, 02, 02, 04, 30);
	}
	
	def "Verify that Time32 converts date correctly"(){
		setup:
		Date time = cal.getTime()
		when:
		def t = new Time32(time)
		
		then:
		t.asElapsedTime() == 192157472L
		
		when:
		Time32 t2 = deserializeFromHex(new Time32(), serializeToHex(t))
		then:
		t2.asDate() == time
		

		when:
		def t3 = new Time32(123L) // test long constructor
		then:
		t3.asElapsedTime() == 123L
		
	}
	
	def "Verify toString"(){
		expect:
		new Time32(cal.getTime()).toString() == "Time32 [timeStamp=Tue Feb 02 02:04:30 CET 2010 (192157472)]"
	}


}
