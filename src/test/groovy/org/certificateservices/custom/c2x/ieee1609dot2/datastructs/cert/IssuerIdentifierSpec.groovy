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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices
import spock.lang.Shared
import spock.lang.Unroll

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices.*

/**
 * Test for IssuerIdentifier
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class 	IssuerIdentifierSpec extends BaseStructSpec {
	
	@Shared HashedId8 h = new HashedId8("SomeHostname".bytes)
	@Shared HashAlgorithm hashAlg = HashAlgorithm.sha256
		
	@Unroll
	def "Verify that IssuerIdentifier is correctly encoded for type #choice"(){
		setup:
		def id
		when:
		if(choice == IssuerIdentifierChoices.self) {
			id = new IssuerIdentifier(value)
		}else{
			id = new IssuerIdentifier(choice,value)
		}
		
		then:
		serializeToHex(id) == encoding
		
		when:
		IssuerIdentifier id2 = deserializeFromHex(new IssuerIdentifier(), encoding)
		
		then:
		
		id2.choice == choice
		id2.type == choice
		if(id2.type == IssuerIdentifierChoices.self){
			assert id2.getHashAlgoritm() == value
		}else{
		  assert id2.getValue() == value
		}
		choice.extension == extension

		where:
		choice                      | value                 | encoding                | extension
		sha256AndDigest             | h                     | "80486f73746e616d65"    | false
		sha384AndDigest             | h                     | "8208486f73746e616d65"  | true
		self                        | hashAlg               | "8100"                  | false
		
	}

	
	def "Verify toString"(){
		expect:
		new IssuerIdentifier(sha256AndDigest,h).toString() == "IssuerIdentifier [sha256AndDigest=[486f73746e616d65]]"
		new IssuerIdentifier(sha384AndDigest,h).toString() == "IssuerIdentifier [sha384AndDigest=[486f73746e616d65]]"
		new IssuerIdentifier(hashAlg).toString() == "IssuerIdentifier [self=sha256]"

	}
	

}
