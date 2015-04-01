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
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.cert.ItsAidPriority;
import org.certificateservices.custom.c2x.its.datastructs.cert.ItsAidPrioritySsp;
import org.certificateservices.custom.c2x.its.datastructs.cert.ItsAidSsp;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAssurance;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttribute;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SubjectAttributeSpec extends BaseStructSpec {
	
	PublicKey publicKey1 = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)))
	PublicKey publicKey2 = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(2)))
	
	
	
	SubjectAttribute sav = new SubjectAttribute(verification_key, publicKey1);
	SubjectAttribute sae = new SubjectAttribute(encryption_key, publicKey2);
	// TODO reconstruction value
	SubjectAttribute sas = new SubjectAttribute(new SubjectAssurance(2, 3));
	SubjectAttribute sal1 = new SubjectAttribute(its_aid_list, [new IntX(1L),new IntX(2L),new IntX(3L)]);
	SubjectAttribute sal2 = new SubjectAttribute(its_aid_ssp_list, [new ItsAidSsp(new IntX(1L), new byte[1]),new ItsAidSsp(new IntX(2L), new byte[2])]);
	SubjectAttribute sal3 = new SubjectAttribute(priority_its_aid_list, [new ItsAidPriority(new IntX(1L), 1),new ItsAidPriority(new IntX(2L), 2)]);
	SubjectAttribute sal4 = new SubjectAttribute(priority_ssp_list, [new ItsAidPrioritySsp(new IntX(1L), 1, new byte[1]),new ItsAidPrioritySsp(new IntX(2L), 2, new byte[2])]);
	
	def "Verify the constructors and getters"(){
		expect:
		sav.subjectAttributeType == verification_key
		sav.publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		
		sae.subjectAttributeType == encryption_key
		sae.publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		
		sas.subjectAttributeType == assurance_level
		sas.assuranceLevel != null
		
		sal1.subjectAttributeType == its_aid_list
		sal1.itsAidList.size() == 3
		
		sal2.subjectAttributeType == its_aid_ssp_list
		sal2.itsAidList.size() == 2
		
		sal3.subjectAttributeType == priority_its_aid_list
		sal3.itsAidList.size() == 2
		
		sal4.subjectAttributeType == priority_ssp_list
		sal4.itsAidList.size() ==  2

		when: 
		new SubjectAttribute(assurance_level, publicKey1);
		then:
		thrown IllegalArgumentException
		when:
		new SubjectAttribute(assurance_level, []);
		then:
		thrown IllegalArgumentException

	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(sav) == "0000000000000000000000000000000000000000000000000000000000000000000001"
		serializeToHex(sae) == "0100000000000000000000000000000000000000000000000000000000000000000002"
		// TODO reconstruction value
		serializeToHex(sas) == "0243"
		serializeToHex(sal1) == "2003010203"
		serializeToHex(sal2) == "210701010002020000"
		serializeToHex(sal3) == "220401010202"
		serializeToHex(sal4) == "2309010101000202020000"
				
	}
	
	def "Verify deserialization"(){
		setup:
	    SubjectAttribute sav2 = deserializeFromHex(new SubjectAttribute(),"0000000000000000000000000000000000000000000000000000000000000000000001");
		SubjectAttribute sae2 = deserializeFromHex(new SubjectAttribute(),"0100000000000000000000000000000000000000000000000000000000000000000002");
	    SubjectAttribute sas2 = deserializeFromHex(new SubjectAttribute(),"0243");
	    SubjectAttribute sal12 = deserializeFromHex(new SubjectAttribute(),"2003010203");
	    SubjectAttribute sal22 = deserializeFromHex(new SubjectAttribute(),"210701010002020000");
		SubjectAttribute sal32 = deserializeFromHex(new SubjectAttribute(),"220401010202");
		SubjectAttribute sal42 = deserializeFromHex(new SubjectAttribute(),"2309010101000202020000");
		expect:
		sav2.subjectAttributeType == verification_key
		sav2.publicKey.publicKey.x.intValue() == 1
		
		sae2.subjectAttributeType == encryption_key
		sae2.publicKey.publicKey.x.intValue() == 2
		
		sas2.subjectAttributeType == assurance_level
		sas.assuranceLevel.confidenceLevel == 3
		
		sal12.subjectAttributeType == its_aid_list
		sal12.itsAidList.size() == 3
		sal12.itsAidList[0] instanceof IntX
		
		sal22.subjectAttributeType == its_aid_ssp_list
		sal22.itsAidList.size() == 2
		sal22.itsAidList[0] instanceof ItsAidSsp
		
		sal32.subjectAttributeType == priority_its_aid_list
		sal32.itsAidList.size() == 2
		sal32.itsAidList[0] instanceof ItsAidPriority
		
		sal42.subjectAttributeType == priority_ssp_list
		sal42.itsAidList.size() == 2
		sal42.itsAidList[0] instanceof ItsAidPrioritySsp

	}

	def "Verify hashCode and equals"(){
		setup:
		SubjectAttribute sav2 = new SubjectAttribute(verification_key, publicKey1);
		expect:
		sav == sav2
		sav != sae
		sav != sas
		sav != sal1
		sav != sal2
		sav != sal3
		sav != sal4
		
		sav.hashCode() == sav2.hashCode()
		sav.hashCode() != sae.hashCode()
		sav.hashCode() != sas.hashCode()
		sav.hashCode() != sal1.hashCode()
		sav.hashCode() != sal2.hashCode()
		sav.hashCode() != sal3.hashCode()
		sav.hashCode() != sal4.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		sav.toString() == "SubjectAttribute [subjectAttributeType=verification_key, key=PublicKey [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], supportedSymmAlg=null]]"
		sae.toString() == "SubjectAttribute [subjectAttributeType=encryption_key, key=PublicKey [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=2, eccPointType=x_coordinate_only], supportedSymmAlg=null]]"
		sas.toString() == "SubjectAttribute [subjectAttributeType=assurance_level, assuranceLevel=SubjectAssurance [subjectAssurance=67 (assuranceLevel=2, confidenceLevel= 3 )]]"
		sal1.toString() == "SubjectAttribute [subjectAttributeType=its_aid_list, itsAidList=[IntX [value=1], IntX [value=2], IntX [value=3]]]"
		sal2.toString() == "SubjectAttribute [subjectAttributeType=its_aid_ssp_list, itsAidList=[ItsAidSsp [itsAid=IntX [value=1], serviceSpecificPermissions=[0]], ItsAidSsp [itsAid=IntX [value=2], serviceSpecificPermissions=[0, 0]]]]"
		sal3.toString() == "SubjectAttribute [subjectAttributeType=priority_its_aid_list, itsAidList=[ItsAidPriority [itsAid=IntX [value=1], maxPriority=1], ItsAidPriority [itsAid=IntX [value=2], maxPriority=2]]]"
		sal4.toString() == "SubjectAttribute [subjectAttributeType=priority_ssp_list, itsAidList=[ItsAidPrioritySsp [itsAid=IntX [value=1], maxPriority=1, serviceSpecificPermissions=[0]], ItsAidPrioritySsp [itsAid=IntX [value=2], maxPriority=2, serviceSpecificPermissions=[0, 0]]]]"
			
	}
}

