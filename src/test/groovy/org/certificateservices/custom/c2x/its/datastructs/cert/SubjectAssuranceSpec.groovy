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
package org.certificateservices.custom.c2x.its.datastructs.cert



import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAssurance;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SubjectAssuranceSpec extends BaseStructSpec{
	
	def "Verify getAssurranceLevel and getConfidence"(){
		expect:
		new SubjectAssurance(1, 3).getAssuranceLevel() == 1
		new SubjectAssurance(5, 3).getAssuranceLevel() == 5
		new SubjectAssurance(5, 1).getConfidenceLevel() == 1
		new SubjectAssurance(2, 3).getConfidenceLevel() == 3
	}
	
	@Unroll
	def "Verify that #subjectAssurance calculates a byte value of: #byteValue for assuranceLevel: #assuranceLevel and confidenceLevel: #confidenceLevel"(){
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
	def "Verify that #subjectAssurance throws IllegalArgumentException on invalid assuranceLevel: #assuranceLevel"(){
		when:
		new SubjectAssurance(assuranceLevel,0)
		then:
		thrown(IllegalArgumentException)
		where:
		assuranceLevel  << [-1,8,10]
	}
	
	@Unroll
	def "Verify that #subjectAssurance throws IllegalArgumentException on invalid confidenceLevel: #confidenceLevel"(){
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
	
	def "Verify hashCode and equals"(){
		setup:
		def o1  = new SubjectAssurance(5, 3);
		def o2  = new SubjectAssurance(5, 3);
		def o3  = new SubjectAssurance(5, 2);
		def o4  = new SubjectAssurance(4, 3);
		expect:
		o1 == o2
		o1 != o3
		o1 != o4
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
		o1.hashCode() != o4.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new SubjectAssurance(5, 3).toString() == "SubjectAssurance [subjectAssurance=163 (assuranceLevel=5, confidenceLevel= 3 )]"
	}

}
