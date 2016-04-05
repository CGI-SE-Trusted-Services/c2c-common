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


import java.security.KeyPair;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.Certificate.Type;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
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
import org.certificateservices.custom.c2x.its.generator.AuthorityCertGenerator
import org.certificateservices.custom.c2x.its.generator.EnrollmentCredentialCertGenerator;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CertificateSpec extends BaseStructSpec {
	
	ValidityRestriction vr1_v1 = new ValidityRestriction(new Time32(1,new Date(1416581892590L)));
	ValidityRestriction vr2_v1 = new ValidityRestriction(new Time32(1,new Date(1416581882582L)),new Time32(1,new Date(1416581892590L)));
	
	ValidityRestriction vr1_v2 = new ValidityRestriction(new Time32(2,new Date(1416581892590L)));
	ValidityRestriction vr2_v2 = new ValidityRestriction(new Time32(2,new Date(1416581882582L)),new Time32(2,new Date(1416581892590L)));
	
	PublicKey publicKey1 = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)))
	
	SubjectAttribute sav = new SubjectAttribute(SubjectAttributeType.verification_key, publicKey1);
	SubjectAttribute sae = new SubjectAttribute(new SubjectAssurance(4, 2));
	SubjectAttribute sal = new SubjectAttribute(SubjectAttributeType.its_aid_ssp_list, [new ItsAidSsp(new IntX(1L), new byte[2])]);
	
	SubjectInfo si = new SubjectInfo(SubjectType.enrollment_credential, "123456789".getBytes());
	SubjectInfo siNull = new SubjectInfo(SubjectType.authorization_ticket, null);
	
	Certificate authCa = genCertificate(1,SubjectType.authorization_authority,"TestCA")
	Certificate rootCa = genCertificate(1,SubjectType.root_ca,"RootCA")
	SignerInfo sic = new SignerInfo(authCa);
	SignerInfo sis = new SignerInfo();
	SignerInfo sicn = new SignerInfo([authCa, rootCa])
	
	Signature sig = new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[32]))
	
	Certificate c1 = new Certificate([sic,sis],si,[sav,sae,sal], [vr1_v1,vr2_v1])
	Certificate c2 = new Certificate(1,[sic,sis],si,[sav,sae,sal], [vr1_v1,vr2_v1])
	Certificate c3 = new Certificate(1,[sic,sis],si,[sav,sae,sal], [vr1_v1,vr2_v1], sig)
	Certificate c4 = new Certificate(Hex.decode("01808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"))
	
	Certificate c1_v2 = new Certificate(sis,si,[sav,sae,sal], [vr1_v2,vr2_v2])
	
	@Shared ITSCryptoManager cryptoManager
	
	@Shared KeyPair rootCAKeys
	@Shared Certificate rootCA

	
	def setupSpec(){
		cryptoManager = new DefaultCryptoManager()
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		AuthorityCertGenerator acg = new AuthorityCertGenerator(cryptoManager);
				
		rootCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		rootCA = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), null, null)
	}
	
	def "Verify the constructors and getters"(){		
		expect:
		c1.version == 1
		verifyCert(c1)
		
		c2.version == 1
		verifyCert(c2)

		c3.version == 1
		verifyCert(c3)
		c3.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		
		c4.version == 1
		verifyCert(c4)
		c4.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		
		c1_v2.version == 2
		c1_v2.getSignerInfos().size() == 1
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
		serializeToHex(c3) == "01808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"		
		serializeToHex(new Certificate(2,[sis],siNull,[sav,sae,sal], [vr1_v2,vr2_v2], sig)) == "020001002b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e00147bf00701147beffd147bf007000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
		
		serializeToHex(c1_v2) == "020000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e00147bf00701147beffd147bf007"
	}
	
	def "Verify deserialization"(){
		setup:
		// Only signed certificates can be deserialized
		Certificate authCa2 = deserializeFromHex(new Certificate(),"01010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000");	    
	    Certificate c23 = deserializeFromHex(new Certificate(),"01808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000");
		Certificate c24 = deserializeFromHex(new Certificate(),"01808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000001002b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000");
		
		Certificate c1_v22 = deserializeFromHex(new Certificate(),"020000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e00147bf00701147beffd147bf007");
		expect:
		true
        authCa2 != null
	
		c23.version == 1
		verifyCert(c23)
		
		c24 != null
		
		c1_v22 != null
		c1_v22.version == 2

	}
	
	def "Verify that IllegalArgumentException is thrown for invalid signer infos for version 2 certificates"(){
		when: "Try to many signer infos"
		new Certificate(2,[sis,sis],si,[sav,sae,sal], [vr1_v1,vr2_v1], sig)
		then:
		thrown IllegalArgumentException
		when: "Try to add certificate signer info"
		new Certificate(2,[sic],si,[sav,sae,sal], [vr1_v1,vr2_v1], sig)
		then:
		thrown IllegalArgumentException
		when: "Try to add certificate chain signer info"
		new Certificate(2,[sicn],si,[sav,sae,sal], [vr1_v1,vr2_v1], sig)
		then:
		thrown IllegalArgumentException
		when: "verify default ver 2 constructor checks signer info type"
		new Certificate(sicn,si,[sav,sae,sal], [vr1_v1,vr2_v1])
		then:
		thrown IllegalArgumentException
	}
	
// TODO This doesn't seem right
//	def "Verify deserialization and serialization of reference ETSI Certificates works"(){
//		when: "Verify Root CA certificate"
//		String rootCertOrgString = "0201000412455453495f506c7567746573745f526f6f748091000004bf8a03e7a5c26ecc9cde8199ac933b4f934ea2e5555acffd71c81e127ef15a75ed5f95ea1ec498d2bd01974676e7812bbffd0cac6f37db20cf8791e3a458a7d901010004bcdc54771cb782683d4cdeca0853d11600756ace9120b672caba69976b145f6f49a72be0141b8ed085371cb33aa4c2dc2c80aee7448a130d07d38cdda65ca78002202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350000041001bca24d594da442a1e653dd618ccddca435ac6308b53018e881dea14a31e64b7d4da721ef2ff7c67563b4bf16ad79b3288a3878c821dfe394c5484ca7f79"
//		Certificate rootcert = deserializeFromHex(new Certificate(),rootCertOrgString);
//		def rootcertString = serializeToHex(rootcert);
//		then:
//		rootCertOrgString == rootcertString
//		when:
//		String aaCertOrgString = "028112020201000412455453495f506c7567746573745f526f6f748091000004bf8a03e7a5c26ecc9cde8199ac933b4f934ea2e5555acffd71c81e127ef15a75ed5f95ea1ec498d2bd01974676e7812bbffd0cac6f37db20cf8791e3a458a7d901010004bcdc54771cb782683d4cdeca0853d11600756ace9120b672caba69976b145f6f49a72be0141b8ed085371cb33aa4c2dc2c80aee7448a130d07d38cdda65ca78002202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350000041001bca24d594da442a1e653dd618ccddca435ac6308b53018e881dea14a31e64b7d4da721ef2ff7c67563b4bf16ad79b3288a3878c821dfe394c5484ca7f790210455453495f506c7567746573745f41418091000004f4c5e1e8650fef248fb90a38499c11fe8e4a58ed25c368ee36790232e0d770f5619f7174da9629f981f5d365e3eddfe406ffe4920c723dad473a87b5b05ae57f010100045b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe5b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe02202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d0052783500000be28371f8b18d411581c10f30310128625f78f9c69761757d58203c6c757f38ec10d683159c9a52bc3f3e9563194ccaf694cadac56cbaee575bc7366f02ea09d"
//		Certificate aacert = deserializeFromHex(new Certificate(),aaCertOrgString);
//		def aacertString = serializeToHex(aacert);
//		then:
//		aacertString == aaCertOrgString
//		when:
//		String atCertOrgString = "020901bae315dc4e2c97f801008095000004b462520bee11df3cd826e969e4db0ba4327e686e2526fa05bffa617773d217fdca45fb75c453430521484332a0835f5bb690201b1ef3d8fe2c43bdf2eb3865a6010100049f803aaf544262eb522c5ce2332f018cac4d9817b6fddda97d12b01bcdaf56f92bf1ea0b3d0d969cb5d3c1d5fce9eba043d340b76ba7f44e4fc83d6f753517cf0220210ac040800100c040810100240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d0052783500000d8dfca3197ff2177e8d7e169266a7e78192f0c656ceb07f1e2035044509c05609c7efb2f953a2019d7a0c7a0cd7ce5a52cc1544ee92cafa74857b1489f419f46"
//		Certificate atcert = deserializeFromHex(new Certificate(),atCertOrgString);
//		def atcertString = serializeToHex(atcert);
//		then:
//		atcertString == atCertOrgString
//	}
	
	
	
	def "Verify toString"(){
		expect:
		c3.toString() == """Certificate [version=1
  signerInfos:
    [type=certificate, certificate=
      [version=1
        signerInfos:
          [type=self]
        subjectInfo:
          [subjectType=authorization_authority, name=TestCA (546573744341)]
        subjectAttributes:
          [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=x_coordinate_only, x=1], supportedSymmAlg=null]],
          [type=assurance_level, assuranceLevel=[value=130 (assuranceLevel=4, confidenceLevel= 2 )]],
          [type=its_aid_ssp_list, itsAidList=[itsAid=[1], serviceSpecificPermissions=0000]]
        validityRestrictions:
          [type=time_end, end_validity=[154277893]],
          [type=time_start_and_end, start_validity=[154277883], end_validity=[154277893]]
        signature:
          [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=1], signatureValue=0000000000000000000000000000000000000000000000000000000000000000]]
      ]
    ],
    [type=self]
  subjectInfo:
    [subjectType=enrollment_credential, name=123456789 (313233343536373839)]
  subjectAttributes:
    [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=x_coordinate_only, x=1], supportedSymmAlg=null]],
    [type=assurance_level, assuranceLevel=[value=130 (assuranceLevel=4, confidenceLevel= 2 )]],
    [type=its_aid_ssp_list, itsAidList=[itsAid=[1], serviceSpecificPermissions=0000]]
  validityRestrictions:
    [type=time_end, end_validity=[154277893]],
    [type=time_start_and_end, start_validity=[154277883], end_validity=[154277893]]
  signature:
    [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=1], signatureValue=0000000000000000000000000000000000000000000000000000000000000000]]
]"""
		c1_v2.toString()  == """Certificate [version=2
  signerInfo:
    [type=self]
  subjectInfo:
    [subjectType=enrollment_credential, name=123456789 (313233343536373839)]
  subjectAttributes:
    [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=x_coordinate_only, x=1], supportedSymmAlg=null]],
    [type=assurance_level, assuranceLevel=[value=130 (assuranceLevel=4, confidenceLevel= 2 )]],
    [type=its_aid_ssp_list, itsAidList=[itsAid=[1], serviceSpecificPermissions=0000]]
  validityRestrictions:
    [type=time_end, end_validity=[Fri Nov 21 15:58:12 CET 2014 (343666695)]],
    [type=time_start_and_end, start_validity=[Fri Nov 21 15:58:02 CET 2014 (343666685)], end_validity=[Fri Nov 21 15:58:12 CET 2014 (343666695)]]
  signature:none
]"""
		
	}

	def "Verify getEncoded"(){
		expect:
		new String(Hex.encode(c3.getEncoded())) == "01808a0201010002065465737443412b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb093218050000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000093132333435363738392b000000000000000000000000000000000000000000000000000000000000000000000102822104010200000e000932180501093217fb09321805000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
	}
	
	def "Verify getCertificateType returns explicit and getPublicKey returns a valid public key"(){
		
		expect:
		c1.certificateType == Type.EXPLICIT
		rootCA.getPublicKey(cryptoManager, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, null, null).encoded == rootCAKeys.publicKey.encoded
	}
	
	def "Verify that getPublicKey throws IllegalArgumentException for invalid arguments"(){
		when:
		rootCA.getPublicKey(null,null,null,null)
		then:
		thrown IllegalArgumentException
		when:
		rootCA.getPublicKey(cryptoManager,null,null,null)
		then:
		thrown IllegalArgumentException
	}
	
	
	def etsi_ts_10309603_rootca = Hex.decode("0200040049000004C75A096E2C522BA46E81B1DE939DBB2253AEA3A3311F2FCEC5B770F08289F314BAD63CE192DD0221DDA60FA6B68942B1CB4F2018519EE13F0ED0B9DCD6CAA7C702C0200224250B0114B12B0316925E8403000000324FA8D25CA88619E29CE89DBF410F6DF555498850341E3791552B473B54168409FEF44BC7910C5D61D7D138B710D2693B37980B287077A70E01A341FD6A2599")
    def etsi_ts_10309603_aa = Hex.decode("0201EA216B4559E86F530200490000048CF311117495D33E83E94C11C63B7D68625F947AF79D4B4E1047FB0D51B0CE8D09E9BA7264854747CAE44E4BC1E7352324D7EED6010EA676579E5E4CCF238AC50280200224250B0114B12B03154E0D830300000055A93ADE010B4D8F17991F351CE39D5E173172B1DD1E6A60E697F9CE94AB5796CB97A9E0332E939A565725B4742AA7EBD22D23C7B9C01CAF33D14A9B1184BD6D")
	def etsi_ts_10309603_ea = Hex.decode("0201EA216B4559E86F5303004900000480466757135F6A24B13CAAD2AC227509E8A737AFE33E84C6E5A1C3884F0D6D548BC95A8ACFAA1A0EDEB728072D3F735FE33AFEBB81C2A1B982DF9B62A48323990280200224250B0114B12B03154E0D830300000016C5DE87824812806755E8684248E963F3E6A53132933F00F388B6BD1B4A84C7781CFA7CB815F0F44C71DCBD18307909011ED3C0172CDC2FD1685336754A4A82")
	def etsi_ts_10309603_at = Hex.decode("020123DB8E573817C90C0100520000042E71E6FA9AA024D0715551338B5F9C989FCE4B0EA03752711C46BEEE86606C4CCF2442E38DDEC0F8B65AC7C02867E427264C46892BEBD245250E9EFEA0BF2D690260210B240301FFFF250401FFFFFF0B0114B12B03154E0D8303000000BC408964E47CBE19257C11D12C6A3695D6F1D996B41A13B1C64E2CE613D654C9D211D9BEB9E74F1CC57C16BCD51881969DE8B0348CE1E3FEE660A44C49002AA1")
	def etsi_ts_10309603_ec = Hex.decode("020122A8E3B1128EF46E000052000004338F2F1AC6A3856360610194A574858FCF2359930438AF7781A4E8B81749D53C6DB6A977BF378767B73DCB7A9485AF8D9C8BA27B5DE36CB254FD6B46038879FF0260210B240301FFFF250401FFFFFF0B0114B12B03154E0D830300000094C5EE437984047CE5B68399FB60D6495451D0B40678C0BEA2F88BF4B80BBC0FB181D4C85BF4BFE3A3B0D458024BCD1D30EF81DA779048F0828480D15BEF9202")
	
	def "Verify interoperability with version 2 certificates generated by ETSI TS 10309603 test suite."(){
		when: "Parse and verify Rootca"
		Certificate rootca = new Certificate(etsi_ts_10309603_rootca)
		//println rootca.toString()
		then:
		rootca.toString() == """Certificate [version=2
  signerInfo:
    [type=self]
  subjectInfo:
    [subjectType=root_ca, name=none]
  subjectAttributes:
    [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=uncompressed, x=90169338189878864184930272103739076268841878698565036698979572946718289425172, y=84508715294585442163546920752985957272580921122488689555010249587325267519431], supportedSymmAlg=null]],
    [type=assurance_level, assuranceLevel=[value=192 (assuranceLevel=6, confidenceLevel= 0 )]],
    [type=its_aid_list, itsAidList=[36], [37]]
  validityRestrictions:
    [type=time_start_and_end, start_validity=[Thu Jan 01 01:00:00 CET 2015 (347155203)], end_validity=[Fri Jan 01 01:00:01 CET 2016 (378691204)]],
    [type=region, region:=[regionType=none]]
  signature:
    [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=22756388512013930214150693089816353427017897499449864270079592220184513091204], signatureValue=09fef44bc7910c5d61d7d138b710d2693b37980b287077a70e01a341fd6a2599]]
]"""
		cryptoManager.verifyCertificate(rootca)
		
		when: "Parse and verify authorization ca certificate "
		Certificate authca = new Certificate(etsi_ts_10309603_aa)
		
		then:
		authca.toString() == """Certificate [version=2
  signerInfo:
    [type=certificate_digest_with_ecdsap256, digest=[ea216b4559e86f53]]
  subjectInfo:
    [subjectType=authorization_authority, name=none]
  subjectAttributes:
    [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=uncompressed, x=63753260438683290880154337523368607659983141014678017625944222807406727450253, y=4483777812183240880827132530992440976515905570577898219531694299197282159301], supportedSymmAlg=null]],
    [type=assurance_level, assuranceLevel=[value=128 (assuranceLevel=4, confidenceLevel= 0 )]],
    [type=its_aid_list, itsAidList=[36], [37]]
  validityRestrictions:
    [type=time_start_and_end, start_validity=[Thu Jan 01 01:00:00 CET 2015 (347155203)], end_validity=[Thu Apr 30 02:00:00 CEST 2015 (357436803)]],
    [type=region, region:=[regionType=none]]
  signature:
    [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=38745595570031425985208607655318917190006580677246981864284405738539804481430], signatureValue=cb97a9e0332e939a565725b4742aa7ebd22d23c7b9c01caf33d14a9b1184bd6d]]
]"""
		cryptoManager.verifyCertificate(authca, rootca)
		
		when:
		Certificate enrollca = new Certificate(etsi_ts_10309603_ea)
		
		then:
		enrollca.toString() == """Certificate [version=2
  signerInfo:
    [type=certificate_digest_with_ecdsap256, digest=[ea216b4559e86f53]]
  subjectInfo:
    [subjectType=enrollment_authority, name=none]
  subjectAttributes:
    [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=uncompressed, x=58020437140621848925725248505391182961120060488558180635553504078714777726292, y=63227247112607954644474492843752226876025037853369669329901550613956959347609], supportedSymmAlg=null]],
    [type=assurance_level, assuranceLevel=[value=128 (assuranceLevel=4, confidenceLevel= 0 )]],
    [type=its_aid_list, itsAidList=[36], [37]]
  validityRestrictions:
    [type=time_start_and_end, start_validity=[Thu Jan 01 01:00:00 CET 2015 (347155203)], end_validity=[Thu Apr 30 02:00:00 CEST 2015 (357436803)]],
    [type=region, region:=[regionType=none]]
  signature:
    [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=10300487381595236557470039686274833734758935630431321931408656281932363629767], signatureValue=781cfa7cb815f0f44c71dcbd18307909011ed3c0172cdc2fd1685336754a4a82]]
]"""
		
    cryptoManager.verifyCertificate(enrollca, rootca)
	
		when:
		Certificate authcrt = new Certificate(etsi_ts_10309603_at)
		
		then:
		authcrt.toString() == """Certificate [version=2
  signerInfo:
    [type=certificate_digest_with_ecdsap256, digest=[23db8e573817c90c]]
  subjectInfo:
    [subjectType=authorization_ticket, name=none]
  subjectAttributes:
    [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=uncompressed, x=21007638911080612169183215625656341341842951580797645828143297171896951401548, y=93692827801175614571043244352467836291393722345216339989096628777914696936809], supportedSymmAlg=null]],
    [type=assurance_level, assuranceLevel=[value=96 (assuranceLevel=3, confidenceLevel= 0 )]],
    [type=its_aid_ssp_list, itsAidList=[itsAid=[36], serviceSpecificPermissions=01ffff], [itsAid=[37], serviceSpecificPermissions=01ffffff]]
  validityRestrictions:
    [type=time_start_and_end, start_validity=[Thu Jan 01 01:00:00 CET 2015 (347155203)], end_validity=[Thu Apr 30 02:00:00 CEST 2015 (357436803)]],
    [type=region, region:=[regionType=none]]
  signature:
    [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=85148842005106593251364200598105705131443719235118201740090389138951747556553], signatureValue=d211d9beb9e74f1cc57c16bcd51881969de8b0348ce1e3fee660a44c49002aa1]]
]"""
		
    cryptoManager.verifyCertificate(authcrt, authca)
	
	when:
	Certificate enrollcrt = new Certificate(etsi_ts_10309603_ec)
	
	then:
	enrollcrt.toString() == """Certificate [version=2
  signerInfo:
    [type=certificate_digest_with_ecdsap256, digest=[22a8e3b1128ef46e]]
  subjectInfo:
    [subjectType=enrollment_credential, name=none]
  subjectAttributes:
    [type=verification_key, key=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, publicKey=[eccPointType=uncompressed, x=23320939511965909676225912664945076167196716252686492265432055137776783971644, y=49624836284869454260910814309251494833288229649548702461024941551174770260479], supportedSymmAlg=null]],
    [type=assurance_level, assuranceLevel=[value=96 (assuranceLevel=3, confidenceLevel= 0 )]],
    [type=its_aid_ssp_list, itsAidList=[itsAid=[36], serviceSpecificPermissions=01ffff], [itsAid=[37], serviceSpecificPermissions=01ffffff]]
  validityRestrictions:
    [type=time_start_and_end, start_validity=[Thu Jan 01 01:00:00 CET 2015 (347155203)], end_validity=[Thu Apr 30 02:00:00 CEST 2015 (357436803)]],
    [type=region, region:=[regionType=none]]
  signature:
    [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=67292014896828826199486517680601739179472381301655821099885068578892901235727], signatureValue=b181d4c85bf4bfe3a3b0d458024bcd1d30ef81da779048f0828480d15bef9202]]
]"""
	
cryptoManager.verifyCertificate(enrollcrt, enrollca)
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

