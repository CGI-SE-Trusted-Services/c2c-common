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

import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for ValidityPeriod
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ValidityPeriodSpec extends BaseStructSpec {

	Time32 start = new Time32(255)
	Duration duration = new Duration(DurationChoices.seconds,10)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		ValidityPeriod v1 = new ValidityPeriod(start,duration)
		then:
		serializeToHex(v1) == "000000ff82000a"
		when:
		ValidityPeriod v2 = deserializeFromHex(new ValidityPeriod(), "000000ff82000a")
		then:
		v2.getStart().getValueAsLong() == 255
		v2.getDuration() == duration
		
	}
	
	def "Verify that both start and duration have to be set or IllegalArgumentException is thrown when encoding"(){
		when:
		new ValidityPeriod(null, duration)
		then:
		thrown IllegalArgumentException
		when:
		new ValidityPeriod(start, null)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new ValidityPeriod(start, duration).toString() == "ValidityPeriod [start=Time32 [timeStamp=Thu Jan 01 01:04:15 CET 2004 (255)], duration=Duration [10 seconds]]"
	}
	

}
