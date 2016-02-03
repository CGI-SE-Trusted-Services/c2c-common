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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for GroupLinkageValue
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class GroupLinkageValueSpec extends BaseStructSpec {

	byte[] jValue = Hex.decode("01020304")
	byte[] value = Hex.decode("010203040506070809")
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		GroupLinkageValue gv1 = new GroupLinkageValue(jValue,value)
		then:
		serializeToHex(gv1) == "01020304010203040506070809"
		when:
		GroupLinkageValue gv2 = deserializeFromHex(new GroupLinkageValue(), "01020304010203040506070809")
		then:
		gv2.getJValue() == jValue
		gv2.getValue() == value
		
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		serializeToHex(new GroupLinkageValue(jValue,null))
		then:
		thrown IOException
		when:
		serializeToHex(new GroupLinkageValue(null,value))
		then:
		thrown IOException
	} 
	
	def "Verify that IllegalArgument is thrown when jvalue or value has wrong size"(){
		when:
		serializeToHex(new GroupLinkageValue(jValue,Hex.decode("0102030405060708")))
		then:
		thrown IllegalArgumentException
		when:
		serializeToHex(new GroupLinkageValue(jValue,Hex.decode("0102030405060708090a")))
		then:
		thrown IllegalArgumentException
		when:
		serializeToHex(new GroupLinkageValue(Hex.decode("010203"),value))
		then:
		thrown IllegalArgumentException
		when:
		serializeToHex(new GroupLinkageValue(Hex.decode("0102030405"),value))
		then:
		thrown IllegalArgumentException
	}
	

	
	def "Verify toString"(){
		expect:
		new GroupLinkageValue(jValue,value).toString() == "GroupLinkageValue [jvalue=01020304, value=010203040506070809]"
	}
	

}
