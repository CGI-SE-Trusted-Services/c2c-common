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


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectInfo;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SubjectInfoSpec extends BaseStructSpec {
	
	SubjectInfo si = new SubjectInfo(SubjectType.enrollment_credential, "123456789".getBytes());
	SubjectInfo siNull = new SubjectInfo(SubjectType.authorization_ticket, null);
	
	def "Verify constructors and getters and setters"(){
		expect:
		si.subjectType == SubjectType.enrollment_credential
		new String(si.subjectName) == "123456789"
		siNull.subjectType == SubjectType.authorization_ticket
		siNull.subjectName.length == 0
		when:
		new SubjectInfo(SubjectType.enrollment_credential, new byte[SubjectInfo.MAX_SUBJECT_NAME_LENGTH +1]);
		then:
		thrown IllegalArgumentException
	
	}

	def "Verify serialization of SubjectInfo"(){
		expect : 
		serializeToHex(si) == "0009313233343536373839"
		serializeToHex(siNull) == "0100"

	}
	
	def "Verify deserialization ofSignature"(){
		when:                                                 // type// size // data
		SubjectInfo si2 = deserializeFromHex(new SubjectInfo(), "00" + "09" + "313233343536373839");
		then:
		si2.subjectType == SubjectType.enrollment_credential
		new String(si2.subjectName) == "123456789"
		when:                                                 // type// size 
		SubjectInfo siNull2 = deserializeFromHex(new SubjectInfo(), "01" + "00" );
		then:
		siNull2.subjectType == SubjectType.authorization_ticket
		siNull2.subjectName.length == 0
	}
	
	def "Verify hashCode and equals"(){
		setup:		
		def o1  = new SubjectInfo(SubjectType.enrollment_credential, "123456789".getBytes());
		def o2  = new SubjectInfo(SubjectType.enrollment_credential, "12345678".getBytes());
		def o3  = new SubjectInfo(SubjectType.authorization_ticket, "123456789".getBytes())
		expect:
		si == o1
		si != siNull
		si != o2
		si != o3
		si.hashCode() == o1.hashCode()
		si.hashCode() != siNull.hashCode()
		si.hashCode() != o2.hashCode()
		si.hashCode() != o3.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		 si.toString() == "SubjectInfo [subjectType=enrollment_credential, subjectName=[49, 50, 51, 52, 53, 54, 55, 56, 57]]";
		 siNull.toString() == "SubjectInfo [subjectType=authorization_ticket, subjectName=[]]";
	}

}
