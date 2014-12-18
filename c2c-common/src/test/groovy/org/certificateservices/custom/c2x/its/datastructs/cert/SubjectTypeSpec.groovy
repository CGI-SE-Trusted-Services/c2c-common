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

import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SubjectTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #subjectType has bytevalue #bytevalue"(){
		expect:
		subjectType.byteValue instanceof Integer
		subjectType.byteValue == bytevalue
		where:
		subjectType             | bytevalue
		enrollment_credential   | 0
		authorization_ticket    | 1
		authorization_authority | 2
		enrollment_authority    | 3
		root_ca                 | 4
		crl_signer              | 5
	}
	
	@Unroll
	def "Verify that SubjectType.getByValue returns #subjectType for #bytevalue"(){
		expect:
		SubjectType.getByValue( bytevalue) == subjectType
		where:
		subjectType             | bytevalue
		enrollment_credential   | 0
		authorization_ticket    | 1
		authorization_authority | 2
		enrollment_authority    | 3
		root_ca                 | 4
		crl_signer              | 5

	}

}
