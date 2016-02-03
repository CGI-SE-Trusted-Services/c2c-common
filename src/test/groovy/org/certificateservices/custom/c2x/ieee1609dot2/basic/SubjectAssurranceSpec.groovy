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
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SubjectAssurrance
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SubjectAssurranceSpec extends BaseStructSpec {

	
	def "Verify getAssurranceLevel and getConfidence"(){
		expect:
		new SubjectAssurance(1, 3).getAssuranceLevel() == 1
		new SubjectAssurance(5, 3).getAssuranceLevel() == 5
		new SubjectAssurance(5, 1).getConfidenceLevel() == 1
		new SubjectAssurance(2, 3).getConfidenceLevel() == 3
	}
	
	@Unroll
	def "Verify that subjectAssurance calculates a byte value of: #byteValue for assuranceLevel: #assuranceLevel and confidenceLevel: #confidenceLevel"(){
		expect:
		(new SubjectAssurance(assuranceLevel,confidenceLevel)).subjectAssurance == byteValue
		where:
		assuranceLevel        | confidenceLevel          | byteValue
		0                     | 0                        | 0b00000000
		0                     | 1                        | 0b00000001
		1                     | 1                        | 0b00100001
		7                     | 3                        | 0b11100011
	}
	
	
	@Unroll
	def "Verify that subjectAssurance throws IllegalArgumentException on invalid assuranceLevel: #assuranceLevel"(){
		when:
		new SubjectAssurance(assuranceLevel,0)
		then:
		thrown(IllegalArgumentException)
		where:
		assuranceLevel  << [-1,8,10]
	}
	
	@Unroll
	def "Verify that subjectAssurance throws IllegalArgumentException on invalid confidenceLevel: #confidenceLevel"(){
		when:
		new SubjectAssurance(0,confidenceLevel)
		then:
		thrown(IllegalArgumentException)
		where:
		confidenceLevel  << [-1,4,10]
	}
	
	@Unroll
	def "Verify that serialization produces correct output"(){
		expect:
		serializeToHex(new SubjectAssurance(assuranceLevel,confidenceLevel)) == expectedSerializedOutputHex
		where:
		assuranceLevel | confidenceLevel | expectedSerializedOutputHex
		0              | 0               | "00"
		0              | 1               | "01"
		7              | 3               | "e3"
		
	}
	
	def "Verify toString"(){
		expect:
		new SubjectAssurance(5, 3).toString() == "SubjectAssurance [subjectAssurance=163 (assuranceLevel=5, confidenceLevel= 3 )]"
	}
	

}
