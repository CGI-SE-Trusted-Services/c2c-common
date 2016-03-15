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

class COERSequenceOfSpec extends BaseStructSpec {
	
	
	@Shared emptySeq = [] as COEREncodable[]
	@Shared seq1 = [new COERInteger(5),new COERInteger(6),new COERInteger(7)] as COEREncodable[]
	@Shared seq2 = [new COERInteger(7),new COERInteger(6),new COERInteger(5)] as COEREncodable[]
	
	@Unroll
	def "Verify that COERSequenceOf is encoded and is decoded back to the same values and that the length is correct."(){
		expect:
		serializeToHex(new COERSequenceOf(sequenceValues)) == encoded
		
		when:
		COERSequenceOf coerSeq = deserializeFromHex(new COERSequenceOf(new COERInteger()), encoded)
		then:
		
		coerSeq.size() == sequenceValues.length
		coerSeq.getSequenceValues() == sequenceValues
		
		where:
		encoded                                                                                        | sequenceValues    
		"0100"                           							     							   | emptySeq
		"0103010501060107"                             												   | seq1
		"0103010701060105"                            												   | seq2
	}
	
	def "Verify that constructor and getter using lists works as well"(){
		when:
		List l = [new COERInteger(5),new COERInteger(6),new COERInteger(7)]
		COERSequenceOf seq = new COERSequenceOf(l)
		then:
		seq.sequenceValues.length == 3
		seq.sequenceValuesAsList == l
	}
	

	def "Verify equals and hashcode"(){
		setup:
		COERSequenceOf coerseq1 = new COERSequenceOf(seq1)
		COERSequenceOf coerseq1_2 = new COERSequenceOf([new COERInteger(5),new COERInteger(6),new COERInteger(7)] as COEREncodable[])
		COERSequenceOf coerseq2 = new COERSequenceOf(seq2)
		expect:
		coerseq1 != coerseq2
		coerseq1 == coerseq1_2
		coerseq1.hashCode() != coerseq2.hashCode()
		coerseq1.hashCode() == coerseq1_2.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		seq1.toString() == "[COERInteger [value=5], COERInteger [value=6], COERInteger [value=7]]"
	}
	

}
