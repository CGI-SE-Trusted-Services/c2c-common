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

class COERNullSpec extends BaseStructSpec {
	
	def "Verify that COERNull with value #value returns #encoded encoded and encoded #encoded generates a #value value"(){
		expect:
		serializeToHex(new COERNull()) == ""
		deserializeFromHex(new COERNull(), "")
	}

	def "Verify equals and hashcode"(){
		expect:
		COERBoolean.TRUE != new COERNull()
		new COERNull() == new COERNull()
		COERBoolean.TRUE.hashCode() != new COERNull().hashCode()
		new COERNull().hashCode() == new COERNull().hashCode()
	}
	
	def "Verify toString"(){
		expect:
		new COERNull().toString() == "COERNull []"
	}
	

}
