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
package org.certificateservices.custom.c2x.asn1.coer

import org.bouncycastle.asn1.ASN1Boolean
import org.certificateservices.custom.c2x.common.BaseStructSpec

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.asn1.coer.COERTag.*

class COERChoiceSpec extends BaseStructSpec {
	
	
	@Shared emptyChoice = new COERChoice(TestCOEREnumeration.class)
	@Shared choice1 = new COERChoice(TestCOEREnumeration.CHOICE1, new COERInteger(5,0,8))
	@Shared choice2 = new COERChoice(TestCOEREnumeration.CHOICE2, new COEROctetStream("test".getBytes()))
	@Shared choice3 = new COERChoice(TestCOEREnumeration.CHOICE3, new COERInteger(9,0,10))
	
	@Unroll
	def "Verify that COERChoice is encoded and is decoded back to the same values"(){
		expect:
		serializeToHex(choice) == encoded
		
		when:
		COERChoice coerChoice = deserializeFromHex(new COERChoice(TestCOEREnumeration.class), encoded)
		then:
		
		coerChoice.getChoice() == choice.getChoice()
		coerChoice.getValue() ==choice.getValue()
		
		where:
		encoded                                                                                        | choice    
		"8005"                                      												   | choice1
		"810474657374"                            		     										   | choice2
        "8209"                                      												   | choice3
	}
	

	

	def "Verify equals and hashcode"(){
		setup:
		COERChoice choice1_2 = new COERChoice(TestCOEREnumeration.CHOICE1, new COERInteger(5,0,8))
		expect:
		choice1 != choice2
		choice1 == choice1_2
		choice1.hashCode() != choice2.hashCode()
		choice1.hashCode() == choice1_2.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		choice1.toString() == "COERChoice [choice=CHOICE1, value=COERInteger [value=5]]"
	}
	

}
