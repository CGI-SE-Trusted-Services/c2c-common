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

import static org.certificateservices.custom.c2x.asn1.coer.COERTag.*

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;

import spock.lang.Shared
import spock.lang.Unroll

class COEREnumerationSpec extends BaseStructSpec {
	
	
	@Shared emptyEnum= new COEREnumeration(SymmAlgorithm.class)
	@Shared enum1 = new COEREnumeration(SymmAlgorithm.aes128Ccm)
	
	@Unroll
	def "Verify that COEREnumeration is encoded and is decoded back to the same values"(){
		expect:
		serializeToHex(enumVal) == encoded
		
		when:
		COEREnumeration coerEnum = deserializeFromHex(new COEREnumeration(SymmAlgorithm.class), encoded)
		then:
	
		coerEnum.getValue() ==enumVal.getValue()
		
		where:
		encoded                                                                                        | enumVal    
		"00"                                      												   | enum1
	}
	

	

	def "Verify equals and hashcode"(){
		setup:
		COEREnumeration enum2 = new COEREnumeration(HashAlgorithm.sha256)
		COEREnumeration enum1_1 = new COEREnumeration(SymmAlgorithm.aes128Ccm)
		expect:
		enum1 != enum2
		enum1 == enum1_1
		enum1.hashCode() != enum2.hashCode()
		enum1.hashCode() == enum1_1.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		enum1.toString() == "COEREnumeration [value=aes128Ccm]"
	}
	

}
