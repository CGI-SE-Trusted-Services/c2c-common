package org.certificateservices.custom.c2x.its.generator;


import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.ws.http.HTTPBinding;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.crypto.CryptoManager;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage;

import spock.lang.Shared;
import spock.lang.Specification;

public class MessageAndCertificateValidationIT extends Specification {
	
	@Shared SecuredMessageGenerator sbg
	
	@Shared KeyFactory keyFactory
	
	@Shared CryptoManager cryptoManager
		
	@Shared Certificate authorizationTicket
	@Shared Certificate enrollmentCredential
	
	@Shared Certificate referenceRootCA
	@Shared Certificate referenceAuthorizationCA
	@Shared Certificate referenceAuthorizationTicket
	@Shared Certificate referenceEnrollmentCA
	@Shared Certificate referenceEnrollmentCredential
	
	@Shared KeyPair rootCAKeys
	@Shared KeyPair authorizationCAKeys
	@Shared KeyPair authorizationTicketKeys
	@Shared KeyPair enrollmentCAVerificationKeys
	@Shared KeyPair enrollmentCAEncryptionKeys
	@Shared KeyPair enrollmentCredentialVerificationKeys
	@Shared KeyPair enrollmentCredentialEncryptionKeys
	
	static final def rootCAPrivateKey="308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420b8ebdb87d2993a42ccf3737b9354f0377570c7d1a06f4a5ac9a0dc0713e1c1f4a00a06082a8648ce3d030107a14403420004cfa82f8ff04ab97dd18ff34486a60c694eeb7e02bfd22ddfe4f6e11e4050ed009f7a04a23e024e79fe62c914bdfa97210932f092c0c2afea334b2939da1e3698"
	static final def rootCAPublicKey="3059301306072a8648ce3d020106082a8648ce3d03010703420004cfa82f8ff04ab97dd18ff34486a60c694eeb7e02bfd22ddfe4f6e11e4050ed009f7a04a23e024e79fe62c914bdfa97210932f092c0c2afea334b2939da1e3698"
	static final def authorizationCAPrivateKey="308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104201ae52827b497f84295e1e83dabdd91300f9c36a366a2718ac23c950440322e75a00a06082a8648ce3d030107a1440342000485a4df9d021921492f4402e8ace722279c4b2a7f9646d0198cffce1b16d8f270e18565624fc3a7383d9e053c4aa175d4cd95896d41802adeaf2847badaafbc9d"
	static final def authorizationCAPublicKey="3059301306072a8648ce3d020106082a8648ce3d0301070342000485a4df9d021921492f4402e8ace722279c4b2a7f9646d0198cffce1b16d8f270e18565624fc3a7383d9e053c4aa175d4cd95896d41802adeaf2847badaafbc9d"
	static final def authorizationTicketPrivateKey="308193020100301306072a8648ce3d020106082a8648ce3d03010704793077020101042092f1177527aa995c8bbe7ec8648abd458dd2fa63faa587bc039bb6a102220fffa00a06082a8648ce3d030107a14403420004593b2191fd35374a394847543ad5a9b7980fbfd9d1357fe165493b6b35cd6e75d7130d9cb36c50a31721a1d271e2868e9dcedd75705842a2410e49a93fef1556"
	static final def authorizationTicketPublicKey="3059301306072a8648ce3d020106082a8648ce3d03010703420004593b2191fd35374a394847543ad5a9b7980fbfd9d1357fe165493b6b35cd6e75d7130d9cb36c50a31721a1d271e2868e9dcedd75705842a2410e49a93fef1556"
	static final def enrollmentCAVerificationPrivateKey="308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420a053fc6cd27b48f8568a0464fe782bb2115a793565f98420901984b274b17a2fa00a06082a8648ce3d030107a1440342000492a8ca67cc1214af8321828f8bf4d8957c232cc46835658eb2a005c86012aff5514eafe22fba6b6bd01ca78c3fc88de355732de58ad50943dee5bffd49c0a3ad"
	static final def enrollmentCAVerificationPublicKey="3059301306072a8648ce3d020106082a8648ce3d0301070342000492a8ca67cc1214af8321828f8bf4d8957c232cc46835658eb2a005c86012aff5514eafe22fba6b6bd01ca78c3fc88de355732de58ad50943dee5bffd49c0a3ad"
	static final def enrollmentCAEncryptionPrivateKey="308193020100301306072a8648ce3d020106082a8648ce3d03010704793077020101042063c889c2213634f35723a55873d03936f42d9f4615dc55d15e866aca65cd9112a00a06082a8648ce3d030107a144034200042dad3d129f88195edaf486f7d1ac314ac16151ef42938c6936a8687f224b1669906dcc48586fad38d00883503ca56d1bc793d9b5f54127b153adaf55536b21ae"
	static final def enrollmentCAEncryptionPublicKey="3059301306072a8648ce3d020106082a8648ce3d030107034200042dad3d129f88195edaf486f7d1ac314ac16151ef42938c6936a8687f224b1669906dcc48586fad38d00883503ca56d1bc793d9b5f54127b153adaf55536b21ae"
	static final def enrollmentCredentialVerificationPrivateKeys="308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104205325cd133deca8e885c52264131fe087715521c4c0c145ca06db3720d54bbecaa00a06082a8648ce3d030107a144034200046cda7dc99d0bf615a07fd39d08b73e43f81336a7699c9c338071ee641da88b5d3ebf9ea607625b63203d4c0eaa85eb90e464d196c8ef71be426b6da433748a37"
	static final def enrollmentCredentialVerificationPublicKeys="3059301306072a8648ce3d020106082a8648ce3d030107034200046cda7dc99d0bf615a07fd39d08b73e43f81336a7699c9c338071ee641da88b5d3ebf9ea607625b63203d4c0eaa85eb90e464d196c8ef71be426b6da433748a37"
	static final def enrollmentCredentialEncryptionPrivateKeys="308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420d6a1da8c360616e8249ca4ed4ddd010b37b7ee29518e10549214ef4bea8c58bca00a06082a8648ce3d030107a14403420004c9372d80dfcc7791a3a3ecea80149b1ce1a7375dc07e96a6fb0cfcdc57893bb437f10fed87b222ce2e23332ab7f629129a7d878c37f761214450fd4ee600e3d5"
	static final def enrollmentCredentialEncryptionPublicKeys="3059301306072a8648ce3d020106082a8648ce3d03010703420004c9372d80dfcc7791a3a3ecea80149b1ce1a7375dc07e96a6fb0cfcdc57893bb437f10fed87b222ce2e23332ab7f629129a7d878c37f761214450fd4ee600e3d5"
	
	static final def referenceRootCACertificateData = "010100040a54657374526f6f74434128000002cfa82f8ff04ab97dd18ff34486a60c694eeb7e02bfd22ddfe4f6e11e4050ed00022020017f09010940aa551c0cadb900001291fce44b8e234fe3afbba46dbad9b6a68bf32c888a8f231e7f1831ebcb3e9972f19675291294c0fc54a4d84856a776610e59f126782c8f5c86f09e99f823d1"
	static final def referenceAuthorizationCACertificateData= "01808502010100040a54657374526f6f74434128000002cfa82f8ff04ab97dd18ff34486a60c694eeb7e02bfd22ddfe4f6e11e4050ed00022020017f09010940aa551c0cadb900001291fce44b8e234fe3afbba46dbad9b6a68bf32c888a8f231e7f1831ebcb3e9972f19675291294c0fc54a4d84856a776610e59f126782c8f5c86f09e99f823d1021354657374417574686f72697a6174696f6e43412800000385a4df9d021921492f4402e8ace722279c4b2a7f9646d0198cffce1b16d8f270022020017f09010940aab91c0c86a90000934106d2f3cea28af695bb5cd139d00d111d96f2c0d259c45be2b5a21a4e0a97b6cb318c6a4e7bf945d1d9fcd800469d77d80798b7bebe88185898edb499dd02"
    static final def referenceAuthorizationTicketCertificateData="0109013c8a43b30038655d010028000002593b2191fd35374a394847543ad5a9b7980fbfd9d1357fe165493b6b35cd6e75022020017f090109d2eed509dc2cd900008a2cb54b3521e2b5c92e0064d3026a897acde809c7adab53cebae230481bcc33c8cdce274fdada02119c6bc518b15767368e65b4e3197e1e557272563f372aca"
	static final def referenceEnrollmentCACertificateData = "01808502010100040a54657374526f6f74434128000002cfa82f8ff04ab97dd18ff34486a60c694eeb7e02bfd22ddfe4f6e11e4050ed00022020017f09010940aa551c0cadb900001291fce44b8e234fe3afbba46dbad9b6a68bf32c888a8f231e7f1831ebcb3e9972f19675291294c0fc54a4d84856a776610e59f126782c8f5c86f09e99f823d1031754657374456e726f6c6c6d656e74417574686f726974794c00000392a8ca67cc1214af8321828f8bf4d8957c232cc46835658eb2a005c86012aff5010100022dad3d129f88195edaf486f7d1ac314ac16151ef42938c6936a8687f224b1669022020017f09010940aab91c0c86a90000f663b1cff08e5e53fa46e65e3295cb5a04deaec4b286f0ef0d347e56bc55789c81d63b725762742e892317891771860577e5edb97cbec82ac9a509ae024e4068"
	static final def referenceEnrollmentCredentialCertificateData = "010901a956158d1055a199001854657374456e726f6c6c6d656e7443726564656e7469616c4c0000036cda7dc99d0bf615a07fd39d08b73e43f81336a7699c9c338071ee641da88b5d01010003c9372d80dfcc7791a3a3ecea80149b1ce1a7375dc07e96a6fb0cfcdc57893bb4022020017f09010940aab91c0c5f99000073b3104b84ebc40bd0653a2c57aa3110bb5596c12031b3b231d4809fcc95cfb2052016467e77f9400f2ce3c7c3d675580affc6eb0936511696cb02cbb3975203"
	
	def setupSpec(){
		// Init crytomanager
		cryptoManager = new DefaultCryptoManager()
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		
		keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		
		// Setup PKI Hierarchy
		AuthorityCertGenerator acg = new AuthorityCertGenerator(cryptoManager);
				
		rootCAKeys = getKeys(rootCAPrivateKey,rootCAPublicKey)
		authorizationCAKeys = getKeys(authorizationCAPrivateKey,authorizationCAPublicKey)
		authorizationTicketKeys = getKeys(authorizationTicketPrivateKey,authorizationTicketPublicKey)
		enrollmentCAVerificationKeys = getKeys(enrollmentCAVerificationPrivateKey,enrollmentCAVerificationPublicKey)
		enrollmentCAEncryptionKeys = getKeys(enrollmentCAEncryptionPrivateKey,enrollmentCAEncryptionPublicKey)
		enrollmentCredentialVerificationKeys = getKeys(enrollmentCredentialVerificationPrivateKeys,enrollmentCredentialVerificationPublicKeys)
		enrollmentCredentialEncryptionKeys = getKeys(enrollmentCredentialEncryptionPrivateKeys,enrollmentCredentialEncryptionPublicKeys)
		
		referenceRootCA = getCert(referenceRootCACertificateData)
		referenceAuthorizationCA = getCert(referenceAuthorizationCACertificateData)
		referenceAuthorizationTicket = getCert(referenceAuthorizationTicketCertificateData)
		referenceEnrollmentCA = getCert(referenceEnrollmentCACertificateData)
		referenceEnrollmentCredential = getCert(referenceEnrollmentCredentialCertificateData)

	}

	// Important Root CA cannot be tested since only the reference Root CA is trusted on the site. 
	
	def "Instructions"(){
		when:
		println "To verify the certificates and secure messages go to https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/"
		println ""
		println "Root CA is already imported and cannot be verified and you need to verify each certificate in hierarchy order"
		println "in order to cache and make the site aware of certificates existence."
		println ""
		println ""
		then:
		true
	}
	
	def "Generate Authorization CA v1 for interoperability testing"(){
		setup:
		AuthorityCertGenerator acg = new AuthorityCertGenerator(cryptoManager);
		
		when:
		Certificate authorizationCA = acg.genAuthorizationAuthorityCA("TestAuthorizationCA".getBytes("UTF-8"), [new BigInteger(127)], 1, 0, new Date(1417536952031L), new Date(1417536952031L + 315350000000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationCAKeys.getPublic(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, null, rootCAKeys.getPrivate(), referenceRootCA)
		println "Data for interoperability testing of Authorization CA v1:"
		println "  Root CA: " + new String(Hex.encode(referenceRootCA.encoded))
		println "  Authorization CA: " + new String(Hex.encode(authorizationCA.encoded))
		println ""
		then:
		cryptoManager.verifyCertificate(authorizationCA)
	}
	
	def "Generate Enrollment Credential v1 for interoperability testing"(){
		setup:
		EnrollmentCredentialCertGenerator eccg = new EnrollmentCredentialCertGenerator(cryptoManager, referenceEnrollmentCA, enrollmentCAVerificationKeys.privateKey)
		
		when:
		Certificate enrollmentCredential = eccg.genEnrollmentCredential(SignerInfoType.certificate_digest_with_ecdsap256 ,"TestEnrollmentCredential".getBytes("UTF-8"), [new BigInteger(127)], 1, 0, new Date(1417536952031L), new Date(1417536952031L + 315340000000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,  enrollmentCredentialVerificationKeys.getPublic(), PublicKeyAlgorithm.ecies_nistp256, enrollmentCredentialEncryptionKeys.getPublic())
		println "Data for interoperability testing of Enrollment Credential v1:"
		println "  Root CA: " + new String(Hex.encode(referenceRootCA.encoded))
		println "  Enrollment CA: " + new String(Hex.encode(referenceEnrollmentCA.encoded))
		println "  Enrollment Credential: " + new String(Hex.encode(enrollmentCredential.encoded))
		println ""
		then:
		cryptoManager.verifyCertificate(enrollmentCredential,referenceEnrollmentCA)
	}
	
	
	def "Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing"(){
		when:
		AuthorizationTicketCertGenerator atcg = new AuthorizationTicketCertGenerator(cryptoManager, referenceAuthorizationCA, authorizationCAKeys.getPrivate())

		println "Data for interoperability testing of Signed SecureMessage v1:"
		println "  Root CA: " + new String(Hex.encode(referenceRootCA.encoded))
		println "  Authorization CA: " + new String(Hex.encode(referenceAuthorizationCA.encoded))

		
		authorizationTicket = atcg.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(127)], 1, 0, new Date(System.currentTimeMillis() - (15L * 60000L)), new Date(System.currentTimeMillis() + (7* 24 * 3600 * 1000L)), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationTicketKeys.getPublic(), null, null)
		println "  Authorization Ticket: " + new String(Hex.encode(authorizationTicket.getEncoded()))

		sbg = new SecuredMessageGenerator(cryptoManager, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,authorizationTicket, authorizationTicketKeys.getPrivate(), null,null);


		SecuredMessage sm = sbg.genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType.certificate_digest_with_ecdsap256, [new HashedId3(cryptoManager.digest(authorizationTicket.getEncoded(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256))])
		println "  CAM Unrecognized Certificate Messages: " + new String(Hex.encode(sm.getEncoded()))
		println ""
		then:
		cryptoManager.verifySecuredMessage(sm, authorizationTicket)
	}
	

	private KeyPair getKeys(String privateKeyData, String publicKeyData){
		def spec = ECNamedCurveTable.getParameterSpec("P-256");
		PublicKey pubkey = keyFactory.generatePublic(new X509EncodedKeySpec(Hex.decode(publicKeyData)));
		PrivateKey privkey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Hex.decode(privateKeyData)));
		return new KeyPair(pubkey, privkey)
	}
	
	private Certificate getCert(String certificateData){
		Certificate cert = new Certificate(Hex.decode(certificateData))
		return cert
	}
}
