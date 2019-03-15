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
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Common help methods for generator tests
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

abstract class BaseCertGeneratorSpec extends BaseStructSpec {

	static int SWEDEN = 752
	
	AuthorityCertGenerator acg
	EnrollmentCertGenerator ecg
	AuthorizationCertGenerator authcg
	SecuredDataGenerator sdg
	SecuredDataGenerator sdg_ecdsaNistP256
	SecuredDataGenerator sdg_ecdsaBrainpoolP256r1
	SecuredDataGenerator sdg_ecdsaBrainpoolP384r1
	SecuredCrlGenerator scg
	
	@Shared Ieee1609Dot2CryptoManager cryptoManager
	@Shared ECQVHelper ecqvHelper;
	
	def setupSpec(){
		cryptoManager = new DefaultCryptoManager()
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		
		ecqvHelper = new ECQVHelper(cryptoManager);
	}
	
	def setup(){
		acg = new AuthorityCertGenerator(cryptoManager)
		ecg = new EnrollmentCertGenerator(cryptoManager)
		authcg = new AuthorizationCertGenerator(cryptoManager)
		sdg_ecdsaNistP256 = new SecuredDataGenerator(SecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaNistP256Signature)
		sdg = sdg_ecdsaNistP256
		sdg_ecdsaBrainpoolP256r1 = new SecuredDataGenerator(SecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaBrainpoolP256r1Signature)
		sdg_ecdsaBrainpoolP384r1 = new SecuredDataGenerator(SecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha384, SignatureChoices.ecdsaBrainpoolP384r1Signature)
		scg = new SecuredCrlGenerator(SecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaNistP256Signature)
	}
	
	protected Certificate genRootCA(KeyPair keys, AlgorithmIndicator alg= PublicVerificationKeyChoices.ecdsaNistP256){
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test RootCA"))
		return acg.genRootCA(id, validityPeriod, region, 7, 0, 3, 4, alg, keys.public, keys.private, null, null, null)
	}
	
	
	protected Certificate genEnrollCA(CertificateType type, AlgorithmIndicator alg, KeyPair signKeys, KeyPair rootCAKeys, Certificate rootCA){
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test EnrollmentCA"))
		
		return acg.genLongTermEnrollmentCA(type, id, validityPeriod, region, null,Hex.decode("010203"), 999, 7,0,3,3,alg,
			signKeys.getPublic(),
			rootCA,
			rootCAKeys.getPublic(),
			rootCAKeys.getPrivate(),
			null,
			null,
			null)
	}
	
	protected Certificate genAuthorizationCA(CertificateType type, AlgorithmIndicator alg, KeyPair signKeys, KeyPair rootCAKeys, Certificate rootCA){
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Authorization CA"))
		
		return acg.genAuthorizationCA(type, id, validityPeriod, region, null,Hex.decode("010203"), 999, 7,0,3,3,alg,
			signKeys.getPublic(),
			rootCA,
			rootCAKeys.getPublic(),
			rootCAKeys.getPrivate(),
			null,
			null,
			null)
	}
	
	protected Certificate genEnrollCert(CertificateType type, AlgorithmIndicator alg, KeyPair signKeys, PublicKey enrollCAPublicKey, PrivateKey enrollCAPrivateKey, Certificate enrollCA, AlgorithmIndicator encAlg= null, PublicKey encPubKey=null){
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Enroll CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSspRange[] subjectPerms = new PsidSspRange[1]
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null))
		return ecg.genEnrollCert(type, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), enrollCA, enrollCAPublicKey, enrollCAPrivateKey, SymmAlgorithm.aes128Ccm, encAlg, encPubKey)
	}
	
	protected byte[] signDataECDSA(byte[] data, PrivateKey privKey){
		Signature ecdsa = Signature.getInstance("SHA256withECDSA","BC");
		
		ecdsa.initSign(privKey)
		
		ecdsa.update(data)
		
		return ecdsa.sign()
	}
	
	protected boolean verifySignedDataECDSA(byte[] data, byte[] signature, PublicKey pk){
		Signature ecdsa = Signature.getInstance("SHA256withECDSA","BC");
		ecdsa.initVerify(pk);
		
		ecdsa.update(data)

		return ecdsa.verify(signature)
	}

}
