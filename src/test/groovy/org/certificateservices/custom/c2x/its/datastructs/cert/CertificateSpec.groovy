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


import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.cert.ItsAidSsp;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAssurance;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttribute;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectInfo;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;
import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestriction;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CertificateSpec extends BaseStructSpec {
	
	ValidityRestriction vr1 = new ValidityRestriction(new Time32(new Date(1416581892590L)));
	ValidityRestriction vr2 = new ValidityRestriction(new Time32(new Date(1416581882582L)),new Time32(new Date(1416581892590L)));
	
	PublicKey publicKey1 = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)))
	
	SubjectAttribute sav = new SubjectAttribute(SubjectAttributeType.verification_key, publicKey1);
	SubjectAttribute sae = new SubjectAttribute(new SubjectAssurance(4, 2));
	SubjectAttribute sal = new SubjectAttribute(SubjectAttributeType.its_aid_ssp_list, [new ItsAidSsp(new IntX(1L), new byte[2])]);
	
	SubjectInfo si = new SubjectInfo(SubjectType.enrollment_credential, "123456789".getBytes());
	SubjectInfo siNull = new SubjectInfo(SubjectType.authorization_ticket, null);
	
	Certificate authCa = genCertificate(SubjectType.authorization_authority,"TestCA")
	SignerInfo sic = new SignerInfo(authCa);
	SignerInfo sis = new SignerInfo();
	
	Signature sig = new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[32]))
	
	Certificate c1 = new Certificate([sic,sis],si,[sav,sae,sal], [vr1,vr2])
	Certificate c2 = new Certificate(2,[sic,sis],si,[sav,sae,sal], [vr1,vr2])
	Certificate c3 = new Certificate(2,[sic,sis],si,[sav,sae,sal], [vr1,vr2], sig)
	Certificate c4 = new Certificate(Hex.decode("02808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"))
	
	def "Verify the constructors and getters"(){		
		expect:
		c1.version == 1
		verifyCert(c1)
		
		c2.version == 2
		verifyCert(c2)

		c3.version == 2
		verifyCert(c3)
		c3.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		
		c4.version == 2
		verifyCert(c4)
		c4.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
	}
	
	def "Verify attachSignature"(){
		expect:
		c1.signature == null
		when:
		c1.attachSignature(sig)
		then:
		c1.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256

		
	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(authCa) == "01010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
		serializeToHex(c1) == "01808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805"
		serializeToHex(c3) == "02808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"		
		serializeToHex(new Certificate(2,[sic,sis],siNull,[sav,sae,sal], [vr1,vr2], sig)) == "02808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000001002b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
	}
	
	def "Verify deserialization"(){
		setup:
		// Only signed certificates can be deserialized
		Certificate authCa2 = deserializeFromHex(new Certificate(),"01010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000");	    
	    Certificate c23 = deserializeFromHex(new Certificate(),"02808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000");
		Certificate c24 = deserializeFromHex(new Certificate(),"02808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000001002b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000");
		expect:
		true
        authCa2 != null
	
		c23.version == 2
		verifyCert(c23)
		
		c24 != null

	}
	

	def "Verify deserialization and serialization of reference ETSI Certificates works"(){
		when: "Verify Root CA certificate"
		String rootCertOrgString = "0201000412455453495f506c7567746573745f526f6f748091000004bf8a03e7a5c26ecc9cde8199ac933b4f934ea2e5555acffd71c81e127ef15a75ed5f95ea1ec498d2bd01974676e7812bbffd0cac6f37db20cf8791e3a458a7d901010004bcdc54771cb782683d4cdeca0853d11600756ace9120b672caba69976b145f6f49a72be0141b8ed085371cb33aa4c2dc2c80aee7448a130d07d38cdda65ca78002202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350000041001bca24d594da442a1e653dd618ccddca435ac6308b53018e881dea14a31e64b7d4da721ef2ff7c67563b4bf16ad79b3288a3878c821dfe394c5484ca7f79"
		Certificate rootcert = deserializeFromHex(new Certificate(),rootCertOrgString);
		def rootcertString = serializeToHex(rootcert);
		then:
		rootCertOrgString == rootcertString
		when:
		String aaCertOrgString = "028112020201000412455453495f506c7567746573745f526f6f748091000004bf8a03e7a5c26ecc9cde8199ac933b4f934ea2e5555acffd71c81e127ef15a75ed5f95ea1ec498d2bd01974676e7812bbffd0cac6f37db20cf8791e3a458a7d901010004bcdc54771cb782683d4cdeca0853d11600756ace9120b672caba69976b145f6f49a72be0141b8ed085371cb33aa4c2dc2c80aee7448a130d07d38cdda65ca78002202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350000041001bca24d594da442a1e653dd618ccddca435ac6308b53018e881dea14a31e64b7d4da721ef2ff7c67563b4bf16ad79b3288a3878c821dfe394c5484ca7f790210455453495f506c7567746573745f41418091000004f4c5e1e8650fef248fb90a38499c11fe8e4a58ed25c368ee36790232e0d770f5619f7174da9629f981f5d365e3eddfe406ffe4920c723dad473a87b5b05ae57f010100045b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe5b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe02202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d0052783500000be28371f8b18d411581c10f30310128625f78f9c69761757d58203c6c757f38ec10d683159c9a52bc3f3e9563194ccaf694cadac56cbaee575bc7366f02ea09d"
		Certificate aacert = deserializeFromHex(new Certificate(),aaCertOrgString);
		def aacertString = serializeToHex(aacert);
		then:
		aacertString == aaCertOrgString
		when:
		String atCertOrgString = "020901bae315dc4e2c97f801008095000004b462520bee11df3cd826e969e4db0ba4327e686e2526fa05bffa617773d217fdca45fb75c453430521484332a0835f5bb690201b1ef3d8fe2c43bdf2eb3865a6010100049f803aaf544262eb522c5ce2332f018cac4d9817b6fddda97d12b01bcdaf56f92bf1ea0b3d0d969cb5d3c1d5fce9eba043d340b76ba7f44e4fc83d6f753517cf0220210ac040800100c040810100240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d0052783500000d8dfca3197ff2177e8d7e169266a7e78192f0c656ceb07f1e2035044509c05609c7efb2f953a2019d7a0c7a0cd7ce5a52cc1544ee92cafa74857b1489f419f46"
		Certificate atcert = deserializeFromHex(new Certificate(),atCertOrgString);
		def atcertString = serializeToHex(atcert);
		then:
		atcertString == atCertOrgString
	}
	
	
	
	def "Verify toString"(){
		expect:
		c3.toString() == "Certificate [version=2, signerInfos=[SignerInfo [signerInfoType=certificate, certificate=Certificate [version=1, signerInfos=[SignerInfo [signerInfoType=self]], subjectInfo=SubjectInfo [subjectType=authorization_authority, subjectName=[84, 101, 115, 116, 67, 65]], subjectAttributes=[SubjectAttribute [subjectAttributeType=verification_key, key=PublicKey [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], supportedSymmAlg=null]], SubjectAttribute [subjectAttributeType=assurance_level, assuranceLevel=SubjectAssurance [subjectAssurance=130 (assuranceLevel=4, confidenceLevel= 2 )]], SubjectAttribute [subjectAttributeType=its_aid_ssp_list, itsAidList=[ItsAidSsp [itsAid=IntX [value=1], serviceSpecificPermissions=[0, 0]]]]], validityRestrictions=[ValidityRestriction [type=time_end, end_validity=Time32 [timeStamp=Fri Nov 21 15:58:12 CET 2014 (154277893)]], ValidityRestriction [type=time_start_and_end, start_validity=Time32 [timeStamp=Fri Nov 21 15:58:02 CET 2014 (154277883)], end_validity=Time32 [timeStamp=Fri Nov 21 15:58:12 CET 2014 (154277893)]]], signature=Signature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=EcdsaSignature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], signatureValue=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]]]], SignerInfo [signerInfoType=self]], subjectInfo=SubjectInfo [subjectType=enrollment_credential, subjectName=[49, 50, 51, 52, 53, 54, 55, 56, 57]], subjectAttributes=[SubjectAttribute [subjectAttributeType=verification_key, key=PublicKey [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], supportedSymmAlg=null]], SubjectAttribute [subjectAttributeType=assurance_level, assuranceLevel=SubjectAssurance [subjectAssurance=130 (assuranceLevel=4, confidenceLevel= 2 )]], SubjectAttribute [subjectAttributeType=its_aid_ssp_list, itsAidList=[ItsAidSsp [itsAid=IntX [value=1], serviceSpecificPermissions=[0, 0]]]]], validityRestrictions=[ValidityRestriction [type=time_end, end_validity=Time32 [timeStamp=Fri Nov 21 15:58:12 CET 2014 (154277893)]], ValidityRestriction [type=time_start_and_end, start_validity=Time32 [timeStamp=Fri Nov 21 15:58:02 CET 2014 (154277883)], end_validity=Time32 [timeStamp=Fri Nov 21 15:58:12 CET 2014 (154277893)]]], signature=Signature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=EcdsaSignature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], signatureValue=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]]]"		
	}

	def "Verify getEncoded"(){
		expect:
		new String(Hex.encode(c3.getEncoded())) == "02808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
	}
	
	private verifyCert(Certificate c){
		assert c.signerInfos.size() == 2
		assert c.signerInfos[0].signerInfoType == SignerInfoType.certificate
		assert c.signerInfos[1].signerInfoType == SignerInfoType.self
		
		assert c.subjectInfo.subjectType == SubjectType.enrollment_credential
		
		assert c.subjectAttributes.size() == 3
		assert c.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		assert c.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
		assert c.subjectAttributes[2].subjectAttributeType == SubjectAttributeType.its_aid_ssp_list
		
		assert c.validityRestrictions.size() == 2
		assert c.validityRestrictions[0].validityRestrictionType == time_end
		assert c.validityRestrictions[1].validityRestrictionType == time_start_and_end
		true
	}
}

