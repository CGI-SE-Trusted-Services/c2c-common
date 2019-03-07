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

import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint16;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Duration
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class DurationSpec extends BaseStructSpec {

	@Unroll
	def "Verify that Duration is correctly encoded for type #choice and value #value"(){
		when:
		def d = new Duration(choice, value)
		
		then:
		d.value instanceof Uint16
		d.valueAsInt == value
		serializeToHex(d) == encoding
		
		when:
		Duration d2 = deserializeFromHex(new Duration(), encoding)
		
		then:
		d.value instanceof Uint16
		d.valueAsInt == value
		d.choice == choice
		d.unit == choice
		!choice.extension
		
		where:
		choice                             | value            | encoding
		DurationChoices.microseconds       | 0                | "800000"
		DurationChoices.microseconds       | 10               | "80000a"
		DurationChoices.milliseconds       | 10               | "81000a"
		DurationChoices.seconds            | 10               | "82000a"
		DurationChoices.minutes            | 10               | "83000a"
		DurationChoices.hours              | 10               | "84000a"
		DurationChoices.sixtyHours         | 10               | "85000a"
		DurationChoices.years              | 10               | "86000a"
		
	}
	
	def "Verify toString"(){
		expect:
		new Duration(DurationChoices.seconds,123).toString() == "Duration [123 seconds]"
	}
	

}
