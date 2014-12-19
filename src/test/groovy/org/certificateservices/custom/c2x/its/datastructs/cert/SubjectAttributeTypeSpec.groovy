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


import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SubjectAttributeTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #subjectAttributeType has bytevalue #bytevalue"(){
		expect:
		subjectAttributeType.byteValue instanceof Integer
		subjectAttributeType.byteValue == bytevalue
		where:
		subjectAttributeType        | bytevalue
		verification_key            | 0
		encryption_key              | 1
		assurance_level             | 2
		reconstruction_value        | 3
		its_aid_list                | 32
		its_aid_ssp_list            | 33
		priority_its_aid_list       | 34
		priority_ssp_list           | 35
	}
	
	@Unroll
	def "Verify that SubjectAttributeType.getByValue returns #subjectAttributeType for #bytevalue"(){
		expect:
		SubjectAttributeType.getByValue( bytevalue) == subjectAttributeType
		where:
		subjectAttributeType        | bytevalue
		verification_key            | 0
		encryption_key              | 1
		assurance_level             | 2
		reconstruction_value        | 3
		its_aid_list                | 32
		its_aid_ssp_list            | 33
		priority_its_aid_list       | 34
		priority_ssp_list           | 35

	}

}
