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

import spock.lang.Specification
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.asn1.coer.COERTag.*

class COERTagSpec extends BaseStructSpec {
	
	
	
	@Unroll
	def "Verify that COERTag with tagClass #tagClass and tagNumber #tagNumber returns #encoded and is decoded back to the same values"(){
		when:
		COERTag coerTag = new COERTag(tagClass, tagNumber)
		then:
		serializeToHex(coerTag) == encoded
		
		when:
		coerTag = deserializeFromHex(new COERTag(), encoded)
		then:
		coerTag.tagClass == tagClass
		coerTag.tagNumber == tagNumber
		
		where:
		encoded      | tagClass                             | tagNumber
		"00"         | UNIVERSIAL_TAG_CLASS                 | 0
		"8f"         | CONTEXT_SPECIFIC_TAG_CLASS           | 15
		"bf8374"     | CONTEXT_SPECIFIC_TAG_CLASS           | 500
		"7f838650"   | APPLICATION_TAG_CLASS                | 50000
		
	}
	

	
	def "Verify equals and hashcode"(){
		setup:
		COERTag c1 = new COERTag(UNIVERSIAL_TAG_CLASS,1)
		COERTag c1_1 = new COERTag(UNIVERSIAL_TAG_CLASS,1)
		COERTag c2 = new COERTag(CONTEXT_SPECIFIC_TAG_CLASS,1)
		COERTag c3 = new COERTag(UNIVERSIAL_TAG_CLASS,2)
		expect:
		c1 != c2
		c1 != c3
		c1 == c1_1
		c1.hashCode() != c2.hashCode()
		c1.hashCode() != c3.hashCode()
		c1.hashCode() == c1_1.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new COERTag(CONTEXT_SPECIFIC_TAG_CLASS,1).toString() == "COERTag [tagClass=128 (CONTEXT_SPECIFIC_TAG_CLASS) , tagNumber=1]"
	}
	

}
