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
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration;
import org.junit.Before;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class DurationSpec extends BaseStructSpec {
	
	def "Verify the constructors and getters"(){
		when:
		Duration d1 = new Duration(100,MINUTES);
		then:
		d1.getDurationValue() == 100
		d1.getUnit() == MINUTES
		d1.getEncodedDuration()== 8292
		when:
		d1 = new Duration(400,YEARS);
		then:
		d1.getDurationValue() == 400
		d1.getUnit() == YEARS
		d1.getEncodedDuration()== 33168
		when:
		d1 = new Duration(350,SECONDS);
		then:
		d1.getDurationValue() == 350
		d1.getUnit() == SECONDS
		d1.getEncodedDuration()== 350
		when:
		d1 = new Duration(6051,HOURS);
		then:
		d1.getDurationValue() == 6051
		d1.getUnit() == HOURS
		d1.getEncodedDuration()== 22435
		when:
		d1 = new Duration(3567,BLOCK_60_HOUR);
		then:
	    d1.getDurationValue() == 3567
		d1.getUnit() == BLOCK_60_HOUR
		d1.getEncodedDuration()== 28143
		when:
		d1 = new Duration(8193,BLOCK_60_HOUR);
		then:
		thrown IllegalArgumentException

	}
	
	@Unroll
	def "Verify Unit enum for #unit has byteValue: #byteValue, number of seconds #seconds and unit encoding mask #mask"(){
		expect:
		unit.byteValue == byteValue
		unit.seconds == seconds
		unit.unitMask == unitMask
		
		where:
		unit               | byteValue | seconds      | unitMask
		SECONDS            | 0         | 1            | 0
		MINUTES            | 1         | 60           | 0x2000
		HOURS              | 2         | 3600         | 0x4000
		BLOCK_60_HOUR      | 3         | 216000       | 0x6000
		YEARS              | 4         | 31556925     | 0x8000
	}
	
	def "Verify serialization"(){
		expect:
		serializeToHex(new Duration(3567,BLOCK_60_HOUR)) == "6def"	
	}
	
	def "Verify deserialization"(){
		expect:
		deserializeFromHex(new Duration(),"6def").unit == BLOCK_60_HOUR
		deserializeFromHex(new Duration(),"6def").durationValue== 3567

	}
	
	def "Verify hashCode and equals"(){
		setup:
		def t1  = new Duration(100,MINUTES);
		def t2  = new Duration(100,MINUTES);
		def t3  = new Duration(101,MINUTES);
		def t4  = new Duration(100,SECONDS);
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
		new Duration(100,MINUTES).toString() == "Duration [encodedDuration=8292 (value=100 MINUTES)]"
	}

}
