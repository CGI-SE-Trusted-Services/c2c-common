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

class COERBooleanSpec extends BaseStructSpec {
	
	
	
	@Unroll
	def "Verify that COERBoolean with value #value returns #encoded encoded and encoded #encoded generates a #value value"(){
		when:
		COERBoolean coerBoolean = new COERBoolean(value)
		then:
		serializeToHex(coerBoolean) == encoded
		
		when:
		coerBoolean = deserializeFromHex(new COERBoolean(), encoded)
		then:
		coerBoolean.isValue() == value
		
		where:
		encoded | value
		"00"    | true
		"ff"    | false
	}
	
	def "Verify that IOException is thrown when deserializing invalid COER boolean value"(){
		when:
		deserializeFromHex(new COERBoolean(), "aa")
		then:
		thrown IOException
	}
	
	def "Verify equals and hashcode"(){
		expect:
		COERBoolean.TRUE != COERBoolean.FALSE
		COERBoolean.TRUE == new COERBoolean(true)
		COERBoolean.TRUE.hashCode() != COERBoolean.FALSE.hashCode()
		COERBoolean.TRUE.hashCode() == new COERBoolean(true).hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new COERBoolean(true).toString() == "COERBoolean [value=true]"
	}
	

}
