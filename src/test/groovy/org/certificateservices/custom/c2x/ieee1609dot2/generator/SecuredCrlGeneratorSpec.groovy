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
package org.certificateservices.custom.c2x.ieee1609dot2.generator

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.common.crypto.ECQVHelper
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion.GeographicRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContents;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfJMaxGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfJMaxGroupSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.ToBeSignedLinkageValueCrl;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType.CrlContentsTypeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlPriorityInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv.CrlPsid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv.SecuredCrl;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier.SignerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator.SignerIdentifierType;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SecuredCrlGenerator
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class SecuredCrlGeneratorSpec extends BaseCertGeneratorSpec {

	@Unroll
	def "Verify that signed SecuredCrl with signed data is generated correctly"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys, PublicVerificationKeyChoices.ecdsaNistP256)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), PublicVerificationKeyChoices.ecdsaNistP256, rootCA)
		PrivateKey enrollCAPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCertKeys, enrollCAPubKey, enrollCAPrivateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAPubKey, PublicVerificationKeyChoices.ecdsaNistP256, enrollCA)
		PrivateKey enrollCertPrivateKey = ecqvHelper.certReceiption(enrollCert, enrollCert.r, PublicVerificationKeyChoices.ecdsaNistP256, enrollCertKeys.privateKey, enrollCAPubKey, enrollCA)
		
		SequenceOfJMaxGroup individual = new SequenceOfJMaxGroup([SequenceOfJMaxGroupSpec.genJMaxGroup(7),SequenceOfJMaxGroupSpec.genJMaxGroup(8)])
		ToBeSignedLinkageValueCrl tbsl = new ToBeSignedLinkageValueCrl(5,6, individual, null)
		
		Time32 issueDate = new Time32(4000)
		Time32  nextCrl = new Time32(8000)
		HashedId8  cracaIdInCrl = new HashedId8(Hex.decode("0102030405060708"))
		CrlPriorityInfo priorityInfo = new CrlPriorityInfo(new Uint8(8))
		CrlContentsType typeSpecific = new CrlContentsType(CrlContentsTypeChoices.fullLinkedCrl, tbsl)
		
		CrlContents crlContents = new CrlContents(new CrlSeries(5), cracaIdInCrl, issueDate, nextCrl, priorityInfo, typeSpecific)
		
		when:
		SecuredCrl sr = scg.genSecuredCrl(crlContents, SignerIdentifierType.HASH_ONLY,[enrollCert, enrollCA, rootCA] as Certificate[], enrollCertPrivateKey)
		
		then:
		sr.getContent().getType() == Ieee1609Dot2ContentChoices.signedData
		SignedData signedData = sr.getContent().getValue()
		signedData.getSignature() != null
		signedData.getSigner().getType() == SignerIdentifierChoices.digest
		verifyHeaderInfo(signedData.getTbsData().getHeaderInfo())
		
		Ieee1609Dot2Data unsecuredData = ((SignedDataPayload) signedData.getTbsData().getPayload()).getData()
		unsecuredData.getContent().getType() == Ieee1609Dot2ContentChoices.unsecuredData
		new CrlContents(unsecuredData.getContent().getValue().getData()).getCrlSeries().getValueAsLong() == 5

		when:
		def certStore = sdg.buildCertStore([enrollCA,enrollCert])
		def trustStore = sdg.buildCertStore([rootCA])
		then:
		scg.verifySecuredCrl(sr,  certStore, trustStore)
		
	}

	private void verifyHeaderInfo(HeaderInfo hi){
		assert hi.getPsid() == new CrlPsid()
		assert hi.getGenerationLocation() == null
		assert hi.getGenerationTime() == null
		assert hi.getEncryptionKey() == null
		assert hi.getMissingCrlIdentifier() == null
		assert hi.getExpiryTime() == null
		assert hi.getP2pcdLearningRequest() == null
	}
}
