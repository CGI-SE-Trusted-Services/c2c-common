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
package org.certificateservices.custom.c2x.ieee1609dot2.cert

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfPsidGroupPermissions class
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfPsidGroupPermissionsSpec extends BaseStructSpec {

	PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
	PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))
	
	
	def "Verify that SequenceOfPsidGroupPermissions is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfPsidGroupPermissions(),"01020081c0c0810102010340")
		then:
		u1.getSequenceValues()[0] == perm1
		u1.getSequenceValues()[1] == perm2
		when:
		def u2 = new SequenceOfPsidGroupPermissions([perm1,perm2] as PsidGroupPermissions[])
		then:
		u2.getSequenceValues()[0] == perm1
		u2.getSequenceValues()[1] == perm2
		
		when:
		def u3 = new SequenceOfPsidGroupPermissions([perm1,perm2])
		then:
		u3.getSequenceValues()[0] == perm1
		u3.getSequenceValues()[1] == perm2
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfPsidGroupPermissions([perm1,perm2]).toString() == "SequenceOfPsidGroupPermissions [[appPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]"
		new SequenceOfPsidGroupPermissions().toString() == "SequenceOfPsidGroupPermissions []"
		new SequenceOfPsidGroupPermissions([perm1]).toString() == "SequenceOfPsidGroupPermissions [[appPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]]]"
		
	
	}
	
	


}
