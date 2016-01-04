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

class COERSequenceSpec extends BaseStructSpec {
	
	
	@Shared COERSequence noOptional = new COERSequence(false)
	@Shared COERSequence noOptionalEmpty = new COERSequence(false)
	@Shared COERSequence seq1 = new COERSequence(false, 3)
	@Shared COERSequence seq1Empty = new COERSequence(false, 3)
	@Shared COERSequence seq2 = new COERSequence(false, 3)
	@Shared COERSequence seq2Empty = new COERSequence(false, 3)
	@Shared COERSequence seq3 = new COERSequence(false, 31)
	@Shared COERSequence seq3Empty = new COERSequence(false, 31)
	
	def setupSpec(){
		noOptional.addField(0, new COERInteger(5), false, new COERInteger(), null)
		noOptional.addField(1, new COERInteger(6), false, new COERInteger(), null)
		noOptionalEmpty.addField(0, false, new COERInteger(), null)
		noOptionalEmpty.addField(1, false, new COERInteger(), null)
		
		seq1.addField(0, new COERInteger(5), false, new COERInteger(), null)
		seq1.addField(1, new COERInteger(6), true, new COERInteger(), null)
		seq1.addField(2, new COERInteger(7), false, new COERInteger(), null)
		seq1Empty.addField(0, null, false, new COERInteger(), null)
		seq1Empty.addField(1, null, true, new COERInteger(), null)
		seq1Empty.addField(2, null, false, new COERInteger(), null)
		
		seq2.addField(0, new COERInteger(5), true, new COERInteger(), null)
		seq2.addField(1, null, true, new COERInteger(), null)
		seq2.addField(2, new COERInteger(7), true, new COERInteger(), null)
		seq2Empty.addField(0, null, true, new COERInteger(), null)
		seq2Empty.addField(1, null, true, new COERInteger(), null)
		seq2Empty.addField(2, null, true, new COERInteger(), null)
		
		seq3.addField(0, new COERInteger(0), true, new COERInteger(), null)
		seq3.addField(1, null, true, new COERInteger(), null)
		seq3.addField(2, new COERInteger(2), true, new COERInteger(), null)
		seq3.addField(3, new COERInteger(3), true, new COERInteger(), null)
		seq3.addField(4, null, true, new COERInteger(), null)
		seq3.addField(5, new COERInteger(5), true, new COERInteger(), null)
		seq3.addField(6, new COERInteger(6), true, new COERInteger(), null)
		seq3.addField(7, null, true, new COERInteger(), null)
		seq3.addField(8, new COERInteger(8), true, new COERInteger(), null)
		seq3.addField(9, new COERInteger(9), true, new COERInteger(), null)
		seq3.addField(10, null, true, new COERInteger(), null)
		seq3.addField(11, new COERInteger(11), true, new COERInteger(), null)
		seq3.addField(12, new COERInteger(12), true, new COERInteger(), null)
		seq3.addField(13, null, true, new COERInteger(), null)
		seq3.addField(14, new COERInteger(14), true, new COERInteger(), null)
		seq3.addField(15, new COERInteger(15), true, new COERInteger(), null)
		seq3.addField(16, null, true, new COERInteger(), null)
		seq3.addField(17, new COERInteger(17), true, new COERInteger(), null)
		seq3.addField(18, new COERInteger(18), true, new COERInteger(), null)
		seq3.addField(19, null, true, new COERInteger(), null)
		seq3.addField(20, new COERInteger(20), true, new COERInteger(), null)
		seq3.addField(21, new COERInteger(21), true, new COERInteger(), null)
		seq3.addField(22, null, true, new COERInteger(), null)
		seq3.addField(23, new COERInteger(23), true, new COERInteger(), null)
		seq3.addField(24, new COERInteger(24), true, new COERInteger(), null)
		seq3.addField(25, null, true, new COERInteger(), null)
		seq3.addField(26, new COERInteger(26), true, new COERInteger(), null)
		seq3.addField(27, new COERInteger(27), true, new COERInteger(), null)
		seq3.addField(28, null, true, new COERInteger(), null)
		seq3.addField(29, new COERInteger(29), true, new COERInteger(), null)
		seq3.addField(30, new COERInteger(30), true, new COERInteger(), null)
		
		seq3Empty.addField(0, true, new COERInteger(), null)
		seq3Empty.addField(1, true, new COERInteger(), null)
		seq3Empty.addField(2, true, new COERInteger(), null)
		seq3Empty.addField(3, true, new COERInteger(), null)
		seq3Empty.addField(4, true, new COERInteger(), null)
		seq3Empty.addField(5, true, new COERInteger(), null)
		seq3Empty.addField(6, true, new COERInteger(), null)
		seq3Empty.addField(7, true, new COERInteger(), null)
		seq3Empty.addField(8, true, new COERInteger(), null)
		seq3Empty.addField(9, true, new COERInteger(), null)
		seq3Empty.addField(10, true, new COERInteger(), null)
		seq3Empty.addField(11, true, new COERInteger(), null)
		seq3Empty.addField(12, true, new COERInteger(), null)
		seq3Empty.addField(13, true, new COERInteger(), null)
		seq3Empty.addField(14, true, new COERInteger(), null)
		seq3Empty.addField(15, true, new COERInteger(), null)
		seq3Empty.addField(16, true, new COERInteger(), null)
		seq3Empty.addField(17, true, new COERInteger(), null)
		seq3Empty.addField(18, true, new COERInteger(), null)
		seq3Empty.addField(19, true, new COERInteger(), null)
		seq3Empty.addField(20, true, new COERInteger(), null)
		seq3Empty.addField(21, true, new COERInteger(), null)
		seq3Empty.addField(22, true, new COERInteger(), null)
		seq3Empty.addField(23, true, new COERInteger(), null)
		seq3Empty.addField(24, true, new COERInteger(), null)
		seq3Empty.addField(25, true, new COERInteger(), null)
		seq3Empty.addField(26, true, new COERInteger(), null)
		seq3Empty.addField(27, true, new COERInteger(), null)
		seq3Empty.addField(28, true, new COERInteger(), null)
		seq3Empty.addField(29, true, new COERInteger(), null)
		seq3Empty.addField(30, true, new COERInteger(), null)
	}
	
	@Unroll
	def "Verify that COERSequence is encoded and is decoded back to the same values and that preample is correct."(){
		expect:
		serializeToHex(sequence) == encoded
		
		when:
		COERSequence coerSeq = deserializeFromHex(emptySeq, encoded)
		then:
		coerSeq.hasExtension == sequence.getHasExtension()
		coerSeq.size() == sequence.size()
		for(int i=0;i<sequence.size(); i++){
			coerSeq.get(i) == sequence.get(i)
		}
		
		where:
		encoded                                                                                        | sequence   | emptySeq   
		"01050106"                       															   | noOptional | noOptionalEmpty
		"40010501060107"                                                                               | seq1       | seq1Empty 
		"5001050107"                                                                                   | seq2       | seq2Empty
		"5b6db6db0100010201030105010601080109010b010c010e010f011101120114011501170118011a011b011d011e" | seq3       | seq3Empty
	}
	
	def "Verify that set and get and size returns the correct values"(){
		expect:
		seq1.size() == 3
		seq1.get(0).valueAsLong == 5
		seq1.get(1).valueAsLong == 6
		when:
		seq1.set(1, new COERInteger(8))
		then:
		seq1.get(1).valueAsLong == 8
		cleanup:
		seq1.set(1,  new COERInteger(6))
	}
	
	def "Verify that using extensions i constructor or encoding thrown IOException because it's not supported"(){
		when:
		COERSequence seq = new COERSequence(true, 1)
		seq.addField(0, true, new COERInteger(), null)
		serializeToHex(seq)
		then:
		thrown IOException
		
		when:
		deserializeFromHex(seq2Empty, "D001050107")
		
		then:
		thrown IOException
	}

	def "Verify that default value is returned if optional is set and exists"(){
		setup:
		COERSequence s = new COERSequence(false, 1)
		s.addField(0, true, new COERInteger(), new COERInteger(4))
		expect:
		s.get(0).valueAsLong == 4
		when:
		s.set(0, new COERInteger(5))
		then:
		s.get(0).valueAsLong == 5
		when:
		s = new COERSequence(false, 1)
		s.addField(0, true, new COERInteger(), null)
		then:
		s.get(0) == null
	}

	
	def "Verify equals and hashcode"(){
		setup:
		COERSequence seq1_2 = new COERSequence(false, 3)
		seq1_2.addField(0, new COERInteger(5), false, new COERInteger(), null)
		seq1_2.addField(1, new COERInteger(6), true, new COERInteger(), null)
		seq1_2.addField(2, new COERInteger(7), false, new COERInteger(), null)
		
		expect:
		seq1 != seq2
		seq1 == seq1_2
		seq1.hashCode() != seq2.hashCode()
		seq1.hashCode() == seq1_2.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		seq2.toString() == "COERSequence [hasExtension=false, [COERInteger [value=5], NULL, COERInteger [value=7]]]"
	}
	

}
