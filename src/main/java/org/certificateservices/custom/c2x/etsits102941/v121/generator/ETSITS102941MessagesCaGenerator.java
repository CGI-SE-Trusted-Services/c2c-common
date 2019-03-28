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
package org.certificateservices.custom.c2x.etsits102941.v121.generator;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.SharedAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.EcSignature;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.enrollment.InnerEcRequestSignedForPop;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.messagesca.EtsiTs102941Data;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.messagesca.EtsiTs102941DataContent;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.ToBeSignedCrl;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.ToBeSignedRcaCtl;
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.ToBeSignedTlmCtl;
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097Data;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedExternalPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.DecryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.CertificateRecipient;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.Recipient;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.SymmetricKeyReceipient;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Class containing methods to generate CA messages according to specification
 * in ETSI TS 102 941 v 1.2.1
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class ETSITS102941MessagesCaGenerator {

    ETSITS102941SecureDataGenerator securedDataGenerator;
    boolean useUncompressed = false;

    /**
     * Constructor using existing ETSISecuredDataGenerator.
     * @param securedDataGenerator the related secured data generator
     */
    public ETSITS102941MessagesCaGenerator(ETSITS102941SecureDataGenerator securedDataGenerator){
        this(securedDataGenerator,false);
    }

    /**
     * Alternative constructor using existing ETSISecuredDataGenerator where it is possible to set that uncommpressed EC points should be used.
     * @param securedDataGenerator
     * @param useUncompressed
     */
    public ETSITS102941MessagesCaGenerator(ETSITS102941SecureDataGenerator securedDataGenerator, boolean useUncompressed){
        this.securedDataGenerator = securedDataGenerator;
        this.useUncompressed = useUncompressed;
    }

    /**
     * Constructor to message generator.
     * @param version       version if Ieee1609Dot2Data to generate.
     * @param cryptoManager the related crypto manager
     * @param hashAlgorithm the related hash algorithm used in messages
     * @param signAlgorithm the related sign algorithm used in messages.
     * @throws SignatureException if internal problems occurred initializing the generator.
     */
    public ETSITS102941MessagesCaGenerator(int version, Ieee1609Dot2CryptoManager cryptoManager, HashAlgorithm hashAlgorithm, Signature.SignatureChoices signAlgorithm) throws SignatureException {
        super();
        this.securedDataGenerator = new ETSITS102941SecureDataGenerator(version, cryptoManager, hashAlgorithm, signAlgorithm);
    }

    /**
     * Alternative constructor where it is possible to set that uncommpressed EC points should be used.
     *
     * @param version       version if Ieee1609Dot2Data to generate.
     * @param cryptoManager the related crypto manager
     * @param hashAlgorithm the related hash algorithm used in messages
     * @param signAlgorithm the related sign algorithm used in messages.
     * @param useUncompressed use uncompressed encoding of public keys.
     * @throws SignatureException if internal problems occurred initializing the generator.
     */
    public ETSITS102941MessagesCaGenerator(int version, Ieee1609Dot2CryptoManager cryptoManager, HashAlgorithm hashAlgorithm, Signature.SignatureChoices signAlgorithm, boolean useUncompressed) throws SignatureException {
        this(version, cryptoManager, hashAlgorithm, signAlgorithm);
        this.useUncompressed = useUncompressed;
    }


    /**
     * Method to generate a initial self signed EnrolmentRequestMessage, for rekeying see separate method according to section 6.2.1 in ETSI TS 102 941 v 1.2.1
     * <p>
     *     <u>
     *         <li>An <i>InnerECRequest</i> structure is built, containing:
     *         <ul>
     *             <li>the identifier of the requesting ITS-S (<i>itsId</i>): this identifier shall be set to the canonical identifier of
     *                 the ITS-S for the initial enrolment with the recipient EA. For a re-enrolment of the ITS-S, the requesting
     *                 ITS-S shall use the identifier of its current valid Enrolment Credential (EC identifier) which is computed
     *                 as the HashedID8 of the Enrolment Credential (as specified in ETSI TS 103 097 [3]);</li>
     *             <li>the <i>certificateFormat</i> which specifies the version used for the certificate format specification. In
     *                 the present document, the certificate format shall be set to ts103097v131 (integer value 1);</li>
     *             <li>the <i>verificationKey</i> for the EC;</li>
     *             <li>the desired attributes (<i>requestedSubjectAttributes</i>)</li>
     *             <li>the <i>requestedSubjectAttributes</i> shall not contain a <i>certIssuePermissions</i> field and the
     *                 fields <i>validityPeriod</i> and <i>region</i> are optional because the EA already knows the ITS-S and can
     *                 set duration and region restrictions on its own.</li>
     *         </ul>
     *         </li>
     *         <li>
     *             For the proof of possession of the verification key pair, an <i>EtsiTs103097DataSigned</i> structure
     *             (InnerECRequestSignedForPOP) is built containing: <i>hashId</i>,<i>tbsData</i>,<i>signer</i> and <i>signature</i>:
     *             <ul>
     *                 <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3];</li>
     *                 <li>in the <i>tbsData</i>:
     *                 <ul>
     *                     <li>the <i>payload</i> shall contain the previous <i>InnerECRequest</i> structure;</li>
     *                     <li>in the <i>headerInfo</i>:
     *                     <ul>
     *                         <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *                         <li>the <i>generationTime</i> shall be present;</li>
     *                         <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *                     </ul>
     *                     </li>
     *                     <li>the <i>signer</i> is set to 'self'.</li>
     *                     <li>the <i>signature</i> over the <i>tbsData</i> computed using the private key corresponding to the new
     *                        <i>verificationKey</i> to be certified (i.e. the request is self-signed) to prove possession of the generated
     *                        verification key pair.</li>
     *                 </ul></li>
     *             </ul>
     *         </li>
     *         <li>An <i>EtsiTs102941Data</i> structure is built, with:
     *         <ul>
     *             <li><i>version</i> is set to v1 (integer value set to 1);</li>
     *             <li>the <i>content</i> is set to the previous signed data structure (InnerECRequestSignedForPOP).</li>
     *         </ul>
     *         </li>
     *         <li>
     *           An <i>EtsiTs103097DataSigned</i> structure is built containing: <i>hashId</i>,<i>tbsData</i>,
     *           <i>signer</i> and <i>signature</i>:
     *           <ul>
     *               <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3];</li>
     *               <li>in the <i>tbsData</i>
     *               <ul>
     *                   <li>the <i>payload</i> field shall contain the previous <i>EtsiTs102941Data</i> structure;</li>
     *                   <li>in the <i>headerInfo</i>:
     *                   <ul>
     *                       <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *                       <li>the <i>generationTime</i> shall be present;</li>
     *                       <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *                   </ul>
     *                   </li>
     *               </ul>
     *               </li>
     *               <li>
     *                   the <i>signer</i> declared as <i>self</i> when the itsId is set to canonical identifier in the initial request.
     *               </li>
     *               <li>
     *                   the <i>signature</i> computed using the canonical private key if the <i>itsId</i> is set to canonical identifier or
     * the current valid EC private key corresponding to the verification public key.
     *               </li>
     *           </ul>
     *         </li>
     *         <li>
     *             An <i>EtsiTs102941DataEncrypted</i> structure is built, with:
     *             <ul>
     *                 <li>the component <i>recipients</i> containing one instance of <i>RecipientInfo</i> of choice
     *                 <i>certRecipInfo</i> containing:
     *                 <ul>
     *                     <li>the hashedId8 of the EA certificate in <i>recipientId</i>; and</li>
     *                     <li>the encrypted data encryption key in <i>encKey</i> the public key to use for encryption
     *                     is the <i>encryptionKey</i> found in the EAcertificate referenced in <i>recipientId</i>;</li>
     *                 </ul></li>
     *                 <li>
     *                     the component <i>ciphertext</i> containing the encrypted representation of the
     *                     <i>EtsiTs102941Signed</i> structure.
     *                 </li>
     *             </ul>
     *         </li>
     *     </u>
     * </p>
     * @param generationTime the message generation time
     * @param innerEcRequest the innerECRequest to include in the message.
     * @param signerPublicKey the enrolment cert public signing key.
     * @param signerPrivateKey the enrolment cert private signing key.
     * @param recipient the recipient EA CA certificate
     * @return encrypted and self signed message containing innerEcRequest.
     * @throws IllegalArgumentException if message contain invalid data
     * @throws IOException if problems occurred serializing the message data
     * @throws GeneralSecurityException if problems occurred encrypting the message.
     */
    public EtsiTs103097DataEncryptedUnicast genInitialEnrolmentRequestMessage(Time64 generationTime, InnerEcRequest innerEcRequest, PublicKey signerPublicKey, PrivateKey signerPrivateKey, Certificate recipient) throws IllegalArgumentException, IOException, GeneralSecurityException {
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        EtsiTs103097DataSigned innerSigned = securedDataGenerator.genEtsiTs103097DataSigned(headerInfo, innerEcRequest.getEncoded(),signerPublicKey,signerPrivateKey);
        InnerEcRequestSignedForPop innerEcRequestSignedForPop = new InnerEcRequestSignedForPop(innerSigned.getProtocolVersion(),innerSigned.getContent());
        EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(Version.V1,new EtsiTs102941DataContent(innerEcRequestSignedForPop));

        return (EtsiTs103097DataEncryptedUnicast) securedDataGenerator.selfSignAndEncryptData(headerInfo,etsiTs102941Data.getEncoded(),signerPublicKey,signerPrivateKey,getRecipientAlgorithm(recipient),new Recipient[]{new CertificateRecipient(recipient)});
    }

    /**
     * Method to generate a rekey EnrolmentRequestMessage. Contains the same data as initial except that outer signer is
     * a hashed reference to the original cert instead of self signed with the original keys.
     * <p>
     * <b>Important:</b> In the InnerECRequest should the requesting
     * ITS-S shall use the identifier of its current valid Enrolment Credential (EC identifier) which is computed
     * as the HashedID8 of the Enrolment Credential (as specified in ETSI TS 103 097 [3]);
     * </p>
     * @param generationTime the message generation time
     * @param innerEcRequest the innerECRequest to include in the message.
     * @param oldCertificateChain the old certificate that should be re-keyed.
     * @param oldSignerPrivateKey the old signing private key that should be re-keyed and used to sign the outer signature.
     * @param signerPublicKey the enrolment cert public signing key.
     * @param signerPrivateKey the enrolment cert private signing key.
     * @param recipient the recipient EA CA certificate
     * @return encrypted and self signed message containing innerEcRequest.
     * @throws IllegalArgumentException if message contain invalid data
     * @throws IOException if problems occurred serializing the message data
     * @throws GeneralSecurityException if problems occurred encrypting the message.
     */
    public EtsiTs103097DataEncryptedUnicast genRekeyEnrolmentRequestMessage(Time64 generationTime, InnerEcRequest innerEcRequest, EtsiTs103097Certificate[] oldCertificateChain, PrivateKey oldSignerPrivateKey, PublicKey signerPublicKey, PrivateKey signerPrivateKey, Certificate recipient) throws IOException, GeneralSecurityException {
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        EtsiTs103097DataSigned innerSigned = securedDataGenerator.genEtsiTs103097DataSigned(headerInfo, innerEcRequest.getEncoded(),signerPublicKey,signerPrivateKey);
        InnerEcRequestSignedForPop innerEcRequestSignedForPop = new InnerEcRequestSignedForPop(innerSigned.getProtocolVersion(),innerSigned.getContent());
        EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(Version.V1,new EtsiTs102941DataContent(innerEcRequestSignedForPop));

        return (EtsiTs103097DataEncryptedUnicast) securedDataGenerator.signAndEncryptData(headerInfo,etsiTs102941Data.getEncoded(), SecuredDataGenerator.SignerIdentifierType.HASH_ONLY,oldCertificateChain,oldSignerPrivateKey,getRecipientAlgorithm(recipient),new Recipient[]{new CertificateRecipient(recipient)});
    }


    /**
     * Method to decrypt and verify a EnrolmentRequestMessage, both initial and rekey.
     *
     * @param enrolmentRequestMessage the complete encrypted enrolmentRequestMessage.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @return a verify result with the decoded CaCertificateRequest and signer identifier and header info.
     * @param receiverStore map of receivers used to decrypt the message.
     * @return verify result, if the message is an initial enrollment the signer information is set to self otherwise
     * it will be set to digest or certificate.
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public RequestVerifyResult<InnerEcRequest> decryptAndVerifyEnrolmentRequestMessage(EtsiTs103097DataEncryptedUnicast enrolmentRequestMessage,Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore, Map<HashedId8, Receiver> receiverStore) throws IllegalArgumentException, GeneralSecurityException, IOException {

        DecryptResult decryptedData = securedDataGenerator.decryptDataWithSecretKey(enrolmentRequestMessage,receiverStore);
        EtsiTs103097DataSigned outerSignature = new EtsiTs103097DataSigned(decryptedData.getData());
        SignedData outerSignedData = getSignedData(outerSignature, "EnrolmentRequestMessage");

        EtsiTs102941Data requestData = parseEtsiTs102941Data(outerSignedData,"EnrolmentRequestMessage", EtsiTs102941DataContent.EtsiTs102941DataContentChoices.enrolmentRequest);
        InnerEcRequestSignedForPop innerEcRequestSignedForPop = requestData.getContent().getInnerEcRequestSignedForPop();

        SignedData innerSignedData = getSignedData(innerEcRequestSignedForPop, "EnrolmentRequestMessage");

        Ieee1609Dot2Data unsecuredData = innerSignedData.getTbsData().getPayload().getData();
        if(unsecuredData.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.unsecuredData){
            throw new IllegalArgumentException("Invalid encoding in EnrolmentRequestMessage, inner signed data should contain payload of unsecuredData.");
        }
        Opaque opaque = (Opaque) unsecuredData.getContent().getValue();
        InnerEcRequest innerEcRequest = new InnerEcRequest(opaque.getData());

        PublicKey innerSignPublicKey = genPublicKey(innerEcRequest.getPublicKeys().getVerificationKey(),"EnrolmentRequestMessage");
        verifySelfSignedMessage(innerEcRequestSignedForPop,innerSignPublicKey,"EnrolmentRequestMessage inner signature");
        if(outerSignedData.getSigner().getType() == SignerIdentifier.SignerIdentifierChoices.self){
            verifySelfSignedMessage(outerSignature,innerSignPublicKey,"EnrolmentRequestMessage outer signature");
        }else{
            verifySignedMessage(outerSignature,certStore,trustStore,"EnrolmentRequestMessage outer signature");
        }

        return new RequestVerifyResult<>(outerSignedData.getSigner(),outerSignedData.getTbsData().getHeaderInfo(),innerEcRequest, genRequestHash(decryptedData.getData()), decryptedData.getSecretKey());
    }

    /**
     * Method to generate a EnrolmentResponseMessage according to ETSI TS 102 941 v 1.2.1.
     * <p>
     * The outermost structure is an <i>EtsiTs103097DataEncrypted</i> structure containing:
     * <ul>
     *     <li>the component <i>recipients</i> containing one instance of <i>RecipientInfo</i> of choice <i>pskRecipInfo</i>,
     *     which contains the HashedId8 of the symmetric key used by the ITS-S to encrypt the <i>EnrolmentRequest</i>
     *     message to which the response is built;</li>
     *     <li>the component <i>ciphertext</i>, once decrypted, contains an <i>EtsiTs103097DataSigned</i> structure.</li>
     * </ul>
     * </p>
     * <p>
     *     If the ITS-S has been able to decrypt the content, this expected EtsiTs103097Data-Signed structure shall contain
     *     <i>hashId</i>,<i>tbsData</i>,<i>signer</i> and <i>signature</i>:
     *     <ul>
     *        <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3];</li>
     *        <li>in the <i>tbsData</i>:
     *        <ul>
     *            <li>the <i>payload</i> shall contain the <i>EtsiTs102941Data</i> structure.</li>
     *            <li>in the <i>headerInfo</i>:
     *            <ul>
     *               <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *               <li>the <i>generationTime</i> shall be present;</li>
     *               <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *            </ul>
     *            </li>
     *        </ul>
     *        <li>the <i>signer</i> declared as <i>digest</i>, containing the HashedId8 of the EA certificate;</li>
     *        <li>the <i>signature</i> over <i>tbsData</i> computed using the EA private key corresponding to its
     *            publicVerificationKey found in the referenced EA certificate.</li>
     *     </ul>
     * </p>
     * <p>
     *     The EtsiTs102941Data shall contain:
     *     <ul>
     *         <li>the <i>version</i> set to v1 (integer value set to 1);</li>
     *         <li>the <i>content</i> set to <i>InnerECResponse</i></li>
     *     </ul>
     * </p>
     * <p>
     *     The <i>InnerECResponse</i> shall contain:
     *     <ul>
     *         <li>the <i>requestHash</i> is the left-most 16 octets of the SHA256 digest of the EtsiTs103097Data - Signed
     *         structure received in the request;</li>
     *         <li>a <i>responseCode</i> indicating the result of the request;</li>
     *         <li>if <i>responseCode</i> is 0, indicating a positive response, then a certificate is returned;</li>
     *         <li>if <i>responseCode</i> is different than 0, indicating a negative response, then no certificate will
     *         be returned.</li>
     *     </ul>
     * </p>
     * @param generationTime the message generation time
     * @param innerEcResponse the innerEcResponse to include in the message.
     * @param signerCertificateChain the EA certificate chain used to signed.
     * @param signerPrivateKey the EA private key signing the message
     * @param preSharedKey the pre shared key used for encryption of messages between the parties. The secret key
     *                     should be the AES key used in the ECIES algorithm for the EnrolmentRequest.
     * @return encrypted and signed message containing innerEcResponse.
     * @throws IllegalArgumentException if message contain invalid data
     * @throws IOException if problems occurred serializing the message data
     * @throws GeneralSecurityException if problems occurred encrypting the message.
     */
    public EtsiTs103097DataEncryptedUnicast genEnrolmentResponseMessage(Time64 generationTime, InnerEcResponse innerEcResponse,
                                                                 EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey,
                                                                 AlgorithmIndicator encryptionAlg, SecretKey preSharedKey) throws IllegalArgumentException, IOException, GeneralSecurityException {
        return genResponseMessage(generationTime, new EtsiTs102941DataContent(innerEcResponse),signerCertificateChain,signerPrivateKey,encryptionAlg,preSharedKey);
    }

    /**
     * Method to decrypt and verify a EnrolmentResponseMessage.
     *
     * @param enrolmentResponseMessage the complete encrypted enrolmentResponseMessage.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @param receiverStore map of receivers used to decrypt the message.
     * @return verify result containing the parsed InnerECResponse
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public VerifyResult<InnerEcResponse> decryptAndVerifyEnrolmentResponseMessage(EtsiTs103097DataEncryptedUnicast enrolmentResponseMessage,
                                                                           Map<HashedId8, Certificate> certStore,
                                                                           Map<HashedId8, Certificate> trustStore,
                                                                           Map<HashedId8, Receiver> receiverStore)
            throws IllegalArgumentException, GeneralSecurityException, IOException {

        byte[] decryptedData = securedDataGenerator.decryptData(enrolmentResponseMessage,receiverStore);
        EtsiTs103097DataSigned outerSignature = new EtsiTs103097DataSigned(decryptedData);
        SignedData outerSignedData = getSignedData(outerSignature, "EnrolmentResponseMessage");

        EtsiTs102941Data requestData = parseEtsiTs102941Data(outerSignedData,"EnrolmentResponseMessage",
                EtsiTs102941DataContent.EtsiTs102941DataContentChoices.enrolmentResponse);
        InnerEcResponse innerEcResponse = requestData.getContent().getInnerEcResponse();

        verifySignedMessage(outerSignature,certStore,trustStore,"EnrolmentResponseMessage");

        return new VerifyResult<>(outerSignedData.getSigner(),
                outerSignedData.getTbsData().getHeaderInfo(),innerEcResponse);
    }

    /**
     * Method to generate a AuthorizationRequestMessage according to ETSI TS 102 941 v 1.2.1.
     * <p>
     *     <ul>
     *         <li>An ECC private key is randomly generated, the corresponding public key (<i>verificationKey</i>)
     *         is provide to be included in the AT.</li>
     *         <li>Optionally, an ECC encryption private key is randomly generated, the corresponding public key(<i>encryptionKey</i>
     *         is provided to be included in the AT.
     *         </li>
     *         <li>A random 32 octets long secret key (hmac-key) is generated.</li>
     *         <li>A tag using the HMAC-SHA256 function is computed using the previously generated hmac-key, on the
     *            concatenation of the serialization of <i>verificationKey</i> and <i>encryptionKey</i> elements
     *            (<i>encryptionKey</i>is optional) this tag is truncated to the leftmost 128 bits and named <i>keyTag</i>
     *            (see FIPS 198-1 [13]). By including the tag in the <i>SharedATRequest</i> structure the integrity as
     *            well as the nonrepudiation of the <i>verificationKey</i> and <i>encryptionKey</i> element is ensured.
     *            The use of an HMAC function ensures that the tag can only be verified by the instances that are in
     *            possession of the hmac-key. By this means the AA can verify that the HMAC value of the public keys
     *            match the given <i>keyTag</i> and the EA is not able to draw conclusions on the keys requested by the
     *            ITS-S.
     *         </li>
     *         <li>
     *                A <i>SharedAtRequest</i> structure is built, with:
     *                <ul>
     *                    <li>the <i>eaId</i> identifying the EA certificate of the EA that can be contacted for validation;</li>
     *                    <li>the calculated <i>keyTag</i></li>
     *                    <li>the <i>certificateFormat</i> which specifies the version used for the certificate format
     *                    specification. In the present document, the certificate format shall be set to ts103097v131
     *                    (integer value 1);</li>
     *                    <li>the desired attributes (<i>requestedSubjectAttributes</i>)</li>
     *                </ul>
     *         </li>
     *         <li>An <i>EtsiTs103097DataSignedExternalPayload</i> structure is built containing:
     *            <i>hashId</i>,<i>tbsData</i>,<i>signer</i> and <i>signature</i>:
     *            <ul>
     *                <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3];</li>
     *                <li>in the <i>tbsData</i>:
     *                  <ul>
     *                    <li>the <i>payload</i> shall contain the <i>EtsiTs102941Data</i> structure.</li>
     *                    <li>in the <i>headerInfo</i>:
     *                    <ul>
     *                      <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *                      <li>the <i>generationTime</i> shall be present;</li>
     *                      <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *                    </ul>
     *                    </li>
     *                 </li>
     *                 </ul>
     *               <il>the <i>signer</i> declared as a digest <i>digest</i> referencing the hashedId8 of the EC certificate;</il>
     *               <li>the <i>signature</i> over <i>tbsData</i> computed using the private key corresponding to the EC's verification
     *                 public key.</li>
     *              </ul>
     *        </li>
     *        <li>An <i>EtsiTs103097DataEncrypted</i> structure (<i>encryptedEcSignature</i>) is built with:
     *             <ul>
     *                 <li>
     *                     the component <i>recipients</i> with one instance of <i>RecipientInfo</i> of choice
     *                     <i>certRecipInfo</i> containing:
     *                     <ul>
     *                         <li>the HashedId8 of the EA certificate in <i>recipientId</i>; and</li>
     *                         <li>the encrypted data encryption key in <i>encKey</i>; the public key to use for
     *                         encryption is the <i>encryptionKey</i> found in the EA certificate referenced in
     *                         <i>recipientId</i>;</li>
     *                     </ul>
     *                 </li>
     *                 <li>
     *                     the component <i>cipherText</i> containing the encrypted representation of the
     *                     <i>EtsiTs103097DataSignedExternalPayload</i> structure;
     *                 </li>
     *                 <li>
     *                     [Itss_NoPrivacy] For special purpose ITS-Ss which do not require privacy and are allowed to be reidentified
     * by the AA, the message structure shall omit the encryption of the signer information and
     * signature by omitting the pervious step.
     *                 </li>
     *             </ul>
     *        </li>
     *        <li>
     *               An <i>InnerAtRequest</i> structure is built, containing:
     *               <ul>
     *                   <li>the publicKeys: a verificationKey requested for certification and an optional encryptionKey to be placed
     *                       in the same certificate;</li>
     *                   <li>the generated <i>hmac-key</i>;</li>
     *                   <li>the <i>SharedATRequest</i> structure;</li>
     *                   <li>[Itss_WithPrivacy] the encrypted detached signature containing the
     *                   <i>EtsiTs103097DataEncrypted</i> structure. (<i>encryptedEcSignature</i>)</li>
     *                   <li>[Itss_NoPrivacy] the not encrypted detached signature containing the
     *                   <i>EtsiTs103097DataSignedExternalPayload</i>.</li>
     *               </ul>
     *        </li>
     *        <li>An <i>EtsiTs102941Data</i> structure is built, with:
     *             <ul>
     *               <li>the <i>version</i> set to v1 (integer value set to 1);</li>
     *               <li>the <i>content</i> set to <i>InnerATRequest</i></li>
     *             </ul>
     *        </li>
     *     </ul>
     * </p>
     *
     * @param generationTime the message generation time
     * @param publicKeys the publicKeys entry used in the InnerAtRequest.
     * @param hmacKey the hmacKey used in the InnerAtRequest.
     * @param sharedAtRequest used in the InnerAtRequest.
     * @param enrolmentCredentialChain the enrolment credential certificate chain.
     * @param enrolmentCredentialPrivateKey the enrolment credential private key.
     * @param authorizationTicketPublicKey used to sign the POP of the requested authorization ticket keys. If null is
     *                                     no POP generated.
     * @param authorizationTicketPrivateKey used to sign the POP of the requested authorization ticket keys. If null is
     *                                      no POP generated.
     * @param authorizationAuthorityRecipient the AA certificate the message should be encrypted to.
     * @param enrolmentAuthorityRecipient the EA certificate, required if withPrivacy is set to true.
     * @param withPrivacy true if EcSignature inside the innerAtRequest should be encrypted when
     *                    sent to Enrolment Authority.
     * @return
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public EtsiTs103097DataEncryptedUnicast genAuthorizationRequestMessage(Time64 generationTime, PublicKeys publicKeys, byte[] hmacKey, SharedAtRequest sharedAtRequest,
                                                                    EtsiTs103097Certificate[] enrolmentCredentialChain, PrivateKey enrolmentCredentialPrivateKey,
                                                                    PublicKey authorizationTicketPublicKey, PrivateKey authorizationTicketPrivateKey,
                                                                    Certificate authorizationAuthorityRecipient,Certificate enrolmentAuthorityRecipient, boolean withPrivacy) throws IllegalArgumentException, IOException, GeneralSecurityException {
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        EcSignature ecSignature;
        EtsiTs103097DataSignedExternalPayload ecSignaturePayload = (EtsiTs103097DataSignedExternalPayload) securedDataGenerator.genReferencedSignedData(headerInfo, sharedAtRequest.getEncoded(), SecuredDataGenerator.SignerIdentifierType.HASH_ONLY, enrolmentCredentialChain,enrolmentCredentialPrivateKey);
        if(withPrivacy){
            EtsiTs103097DataEncrypted encryptedEcSignature = (EtsiTs103097DataEncrypted) securedDataGenerator.encryptData(getRecipientAlgorithm(enrolmentAuthorityRecipient),
                    ecSignaturePayload.getEncoded(),
                    new Recipient[] {new CertificateRecipient(enrolmentAuthorityRecipient)});
            ecSignature = new EcSignature(encryptedEcSignature);
        }else{
            ecSignature = new EcSignature(ecSignaturePayload);
        }
        InnerAtRequest innerAtRequest = new InnerAtRequest(publicKeys,hmacKey,sharedAtRequest,ecSignature);
        EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(Version.V1, new EtsiTs102941DataContent(innerAtRequest));

        byte[] data = etsiTs102941Data.getEncoded();
        if(authorizationTicketPublicKey != null && authorizationTicketPrivateKey != null) {
            Ieee1609Dot2Data popData = securedDataGenerator.genSignedData(headerInfo, data, authorizationTicketPublicKey, authorizationTicketPrivateKey);
            data = popData.getEncoded();
        }

        return (EtsiTs103097DataEncryptedUnicast) securedDataGenerator.encryptData(getRecipientAlgorithm(authorizationAuthorityRecipient),
                data,
                new Recipient[] {new CertificateRecipient(authorizationAuthorityRecipient)});

    }

    /**
     * Method to decrypt and verify a AuthorizationRequestMessage.
     *
     * @param authorizationRequestMessage the complete encrypted AuthorizationRequestMessage.
     * @return a verify result with the decoded InnerAtRequest and signer identifier, header info, secret key and requestHash.
     * @param receiverStore map of receivers used to decrypt the message.
     * @return verify result containing the parsed InnerECResponse, if no POP is expected is header info and signer set to null.
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public RequestVerifyResult<InnerAtRequest> decryptAndVerifyAuthorizationRequestMessage(EtsiTs103097DataEncryptedUnicast authorizationRequestMessage,
                                                                           boolean expectPoP,
                                                                           Map<HashedId8, Receiver> receiverStore)
            throws IllegalArgumentException, GeneralSecurityException, IOException {

        DecryptResult decryptedData = securedDataGenerator.decryptDataWithSecretKey(authorizationRequestMessage,receiverStore);

        byte[] requestHash = genRequestHash(decryptedData.getData());
        if(expectPoP){
            EtsiTs103097DataSigned popSignature = new EtsiTs103097DataSigned(decryptedData.getData());
            SignedData signedData = getSignedData(popSignature, "AuthorizationRequestMessage");
            EtsiTs102941Data etsiTs102941Data = parseEtsiTs102941Data(signedData,"AuthorizationRequestMessage", EtsiTs102941DataContent.EtsiTs102941DataContentChoices.authorizationRequest);
            InnerAtRequest innerAtRequest = etsiTs102941Data.getContent().getInnerAtRequest();
            PublicKey popSignerKey = genPublicKey(innerAtRequest.getPublicKeys().getVerificationKey(),"AuthorizationRequestMessage");
            verifySelfSignedMessage(popSignature,popSignerKey,"AuthorizationRequestMessagePoP");

            return new RequestVerifyResult<>(signedData.getSigner(),signedData.getTbsData().getHeaderInfo(),innerAtRequest,requestHash,decryptedData.getSecretKey());
        }else{
            EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(decryptedData.getData());
            if(etsiTs102941Data.getContent().getType() != EtsiTs102941DataContent.EtsiTs102941DataContentChoices.authorizationRequest){
                throw new IllegalArgumentException("Invalid encoding in AuthorizationRequestMessage, signed EtsiTs102941Data should be of type " + EtsiTs102941DataContent.EtsiTs102941DataContentChoices.authorizationRequest + ".");
            }
            return new RequestVerifyResult<>(null,null,etsiTs102941Data.getContent().getInnerAtRequest(), requestHash, decryptedData.getSecretKey());

        }
    }

    /**
     * Method that decrypts (if private) and verifies a ecSignature element from a innerATRequest or an
     * AuthorizationValidationRequest.
     *
     * @param ecSignature ecSignature in innerATRequest or AuthorizationValidationRequest
     * @param expectPrivacy if the signature is expected to be private.
     * @param enrolmentCACertStore the cert store containing the Enrollment CAs known certificates.
     * @param enrolmentCATrustStore the trust store containing root CA certificates.
     * @param enrolmentCAReceiverStore the decryption key store.
     * @return verify result containing header and signer info.
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public VerifyResult<EcSignature> decryptAndVerifyECSignature(EcSignature ecSignature, SharedAtRequest sharedAtRequest, boolean expectPrivacy,
                                                          Map<HashedId8, Certificate> enrolmentCACertStore,
                                                          Map<HashedId8, Certificate> enrolmentCATrustStore,
                                                          Map<HashedId8, Receiver> enrolmentCAReceiverStore) throws IllegalArgumentException, GeneralSecurityException, IOException {

        if(expectPrivacy && ecSignature.getType() == EcSignature.EcSignatureChoices.ecSignature){
            throw new IllegalArgumentException("Invalid InnerATRequest received, ECSignature should be encrypted.");
        }
        EtsiTs103097DataSignedExternalPayload ecSignaturePayload;
        if(ecSignature.getType() == EcSignature.EcSignatureChoices.ecSignature){
            ecSignaturePayload = ecSignature.getEcSignature();
        }else{
            byte[] decryptedData = securedDataGenerator.decryptData(ecSignature.getEncryptedEcSignature(), enrolmentCAReceiverStore);
            ecSignaturePayload = new EtsiTs103097DataSignedExternalPayload(decryptedData);
        }
        if(!securedDataGenerator.verifyReferencedSignedData(ecSignaturePayload,sharedAtRequest.getEncoded(),enrolmentCACertStore,enrolmentCATrustStore)){
            throw new SignatureException("Invalid external payload signature in ec signature of innerAtRequest.");
        }
        if(ecSignaturePayload.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData){
            throw new IllegalArgumentException("Invalid encoding in innerAtRequest, message type must be signed data");
        }
        SignedData signedData = (SignedData) ecSignaturePayload.getContent().getValue();
        if(signedData.getTbsData().getPayload().getExtDataHash() == null){
            throw new IllegalArgumentException("Invalid encoding in innerAtRequest SignedData, extDataHash field cannot be null");
        }
        return new VerifyResult<>(signedData.getSigner(),signedData.getTbsData().getHeaderInfo(),ecSignature);
    }


    /**
     * Method to generate a AuthorizationResponseMessage according to ETSI TS 102 941 v 1.2.1.
     * <p>
     *     <ul>
     *         <li>The outermost structure is an <i>EtsiTs103097DataEncrypted</i> structure with:
     *         <ul>
     *             <li>the componen <i>recipients</i> containing one instance of <i>RecipientInfo</i>
     *             of choice <i>pskRecipInfo</i>, which contains the HashedId8 of the symmetric key used by the ITS-S
     *             to encrypt the <i>AuthorizationRequest</i> message to which the response is built;</li>
     *             <li>the component <i>ciphertext</i> once decrypted, contains an <i>EtsiTs103097DataSigned</i>
     *             structure.</li>
     *         </ul>
     *         </li>
     *     </ul>
     * </p>
     * <p>
     *     If the ITS-S has been able to decrypt the content, this expected EtsiTs103097Data-Signed structure shall contain
     *     <i>hashId</i>,<i>tbsData</i>,<i>signer</i> and <i>signature</i>:
     *     <ul>
     *        <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3];</li>
     *        <li>in the <i>tbsData</i>:
     *        <ul>
     *            <li>the <i>payload</i> shall contain the <i>EtsiTs102941Data</i> structure.</li>
     *            <li>in the <i>headerInfo</i>:
     *            <ul>
     *               <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *               <li>the <i>generationTime</i> shall be present;</li>
     *               <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *            </ul>
     *            </li>
     *        </ul>
     *        <li>the <i>signer</i> declared as <i>digest</i>, containing the HashedId8 of the AA certificate;</li>
     *        <li>the <i>signature</i> over <i>tbsData</i> computed using the AA private key corresponding to its
     *            publicVerificationKey found in the referenced AA certificate.</li>
     *     </ul>
     * </p>
     * <p>
     *     The <i>authorizationResponse</i> shall contain:
     *     <ul>
     *         <li>the <i>requestHash</i> is the left-most 16 octets of the SHA256 digest of the following structure received in the
     *         request:
     *         <ul>
     *             <li>EtsiTs102941Data structure received in the request if the POP signature is absent (see Figure 17);</li>
     *             <li>EtsiTs103097Data - Signed if POP signature is present (see Figure 18);</li>
     *         </ul>
     *         </li>
     *         <li>A <i>responseCode</i> indicating the result of the request.</li>
     *         <li>If <i>responseCode</i> is 0, indicating a positive response, then a certificate is returned.</li>
     *         <li>If <i>responseCode</i> is different than 0, indicating a negative response, then no certificate will be returned.</li>
     *     </ul>
     * </p>
     * @param generationTime the message generation time
     * @param innerAtResponse the innerAtResponse to include in the message.
     * @param signerCertificateChain the AA certificate chain used to signed.
     * @param signerPrivateKey the AA private key signing the message
     * @param preSharedKey the pre shared key used for encryption of messages between the parties. The secret key
     *                     should be the AES key used in the ECIES algorithm for the AuthorizationRequest.
     * @return encrypted and signed message containing innerEcResponse.
     * @throws IllegalArgumentException if message contain invalid data
     * @throws IOException if problems occurred serializing the message data
     * @throws GeneralSecurityException if problems occurred encrypting the message.
     */
    public EtsiTs103097DataEncryptedUnicast genAuthorizationResponseMessage(Time64 generationTime, InnerAtResponse innerAtResponse,
                                                                 EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey,
                                                                 AlgorithmIndicator encryptionAlg, SecretKey preSharedKey) throws IllegalArgumentException, IOException, GeneralSecurityException {
        return genResponseMessage(generationTime, new EtsiTs102941DataContent(innerAtResponse),signerCertificateChain,signerPrivateKey,encryptionAlg,preSharedKey);
    }

    /**
     * Method to decrypt and verify a AuthorizationResponseMessage.
     *
     * @param authorizationResponseMessage the complete encrypted authorizationResponseMessage.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @param receiverStore map of receivers used to decrypt the message.
     * @return verify result containing the parsed InnerAtResponse
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public VerifyResult<InnerAtResponse> decryptAndVerifyAuthorizationResponseMessage(EtsiTs103097DataEncryptedUnicast authorizationResponseMessage,
                                                                           Map<HashedId8, Certificate> certStore,
                                                                           Map<HashedId8, Certificate> trustStore,
                                                                           Map<HashedId8, Receiver> receiverStore)
            throws IllegalArgumentException, GeneralSecurityException, IOException {

        byte[] decryptedData = securedDataGenerator.decryptData(authorizationResponseMessage,receiverStore);
        EtsiTs103097DataSigned outerSignature = new EtsiTs103097DataSigned(decryptedData);
        SignedData outerSignedData = getSignedData(outerSignature, "AuthorizationResponseMessage");

        EtsiTs102941Data requestData = parseEtsiTs102941Data(outerSignedData,"AuthorizationResponseMessage",
                EtsiTs102941DataContent.EtsiTs102941DataContentChoices.authorizationResponse);
        InnerAtResponse innerAtResponse = requestData.getContent().getInnerAtResponse();

        verifySignedMessage(outerSignature,certStore,trustStore,"AuthorizationResponseMessage");

        return new VerifyResult<>(outerSignedData.getSigner(),
                outerSignedData.getTbsData().getHeaderInfo(),innerAtResponse);
    }

    /**
     * Method to generate a AuthorizationValidationRequestMessage according to ETSI TS 102 941 v 1.2.1.
     * <p>
     *     To create an <i>AuthorizationValidationRequest</i>, the AA shall follow this process:
     *     <ul>
     *         <li>An <i>AuthorizationValidationRequest</i> structure is built, with:
     *         <ul>
     *             <li>in the component <i>sharedAtRequest</i>, the <i>sharedAtRequest</i> component from the
     *               <i>InnerAtRequest</i> received in the <i>AuthorizationRequestMessage</i> or
     *               <i>AuthorizationRequestMessagePop</i>:
     *             </li>
     *             <li>in the component <i>ecSignature</i>, the <i>ecSignature</i> component from the
     *               <i>InnerAtRequest</i> received in the <i>AuthorizationRequestMessage</i>or
     *               <i>AuthorizationRequestMessagePop</i>
     *             </li>
     *         </ul>
     *         </li>
     *         <li>
     *             An <i>EtsiTs102941Data</i> structure is built, with:
     *             <ul>
     *                 <li>the version set to v1 (integer value set to 1);</li>
     *                 <li>the content set to the previous data structure(<i>AuthorizationValidationRequest</i>)</li>
     *             </ul>
     *         </li>
     *         <li>An <i>EtsiTs103097DataEncrypted</i> with:
     *         <ul>
     *             <li>the component <i>recipients</i> containing one instance of <i>RecipientInfo</i>
     *             of choice <i>certRecipInfo</i>, containing:
     *             <ul>
     *                 <li>the hashedId8 of the EA certificate in <i>recipientId</i></li>
     *                 <li>and the encrypted data encryption key in <i>encKey</i>; the public key to use for encryption
     *                 is the <i>encryptionKey</i> found in the EA certificate referenced in <i>recipientId</i>
     *                 </li>
     *             </ul>
     *             </li>
     *             <li>
     *               the component <i>cipherText</i> containing the encrypted representation of the
     *               <i>EtsiTs103097DataSignedExternalPayload</i> structure;
     *             </li>
     *         </ul>
     *         </li>
     *         <li>
     *     An <i>EtsiTs103097Data-Signed</i> structure is built containing <i>hashId</i>,<i>tbsData</i>,
     *     <i>signer</i> and <i>signature</i>:
     *     <ul>
     *        <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3];</li>
     *        <li>in the <i>tbsData</i>:
     *        <ul>
     *            <li>the <i>payload</i> shall contain the previous <i>EtsiTs102941Data</i> structure.</li>
     *            <li>in the <i>headerInfo</i>:
     *            <ul>
     *               <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *               <li>the <i>generationTime</i> shall be present;</li>
     *               <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *            </ul>
     *            </li>
     *        </ul>
     *        <li>the <i>signer</i> declared as <i>digest</i>, containing the HashedId8 of the AA certificate;</li>
     *        <li>the <i>signature</i> over <i>tbsData</i> computed using the AA private key corresponding to its
     *            publicVerificationKey found in the AA certificate.</li>
     *     </ul>
     *         </li>
     *     </ul>
     * </p>
     *
     * @param generationTime the message generation time
     * @param authorizationValidationRequest the authorizationValidationRequest to include in the message.
     * @param authorizationCACredentialChain the AA certificate chain used to signed.
     * @param authorizationCAPrivateKey the AA private key signing the message
     * @param enrolmentAuthorityRecipient the EA reciver certificate.
     * @return encrypted and signed message containing AuthorizationValidationRequest.
     * @throws IllegalArgumentException if message contain invalid data
     * @throws IOException if problems occurred serializing the message data
     * @throws GeneralSecurityException if problems occurred encrypting the message.
     */
    public EtsiTs103097DataEncryptedUnicast genAuthorizationValidationRequest(Time64 generationTime, AuthorizationValidationRequest authorizationValidationRequest,
                                                                              EtsiTs103097Certificate[] authorizationCACredentialChain, PrivateKey authorizationCAPrivateKey,
                                                                              Certificate enrolmentAuthorityRecipient) throws IllegalArgumentException, IOException, GeneralSecurityException {
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(Version.V1,new EtsiTs102941DataContent(authorizationValidationRequest));
        AlgorithmIndicator encAlg = getRecipientAlgorithm(enrolmentAuthorityRecipient);
        return (EtsiTs103097DataEncryptedUnicast) securedDataGenerator.signAndEncryptData(headerInfo,etsiTs102941Data.getEncoded(),
                SecuredDataGenerator.SignerIdentifierType.HASH_ONLY,
                authorizationCACredentialChain,authorizationCAPrivateKey,
                encAlg,new Recipient[]{new CertificateRecipient(enrolmentAuthorityRecipient)});
    }

    /**
     * Method to decrypt and verify a AuthorizationValidationRequestMessage.
     *
     * @param authorizationValidationRequestMessage the complete encrypted AuthorizationValidationRequestMessage.
     * @param certStore a list of known certificates that can be used to build a certificate path to verify signature (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @param receiverStore map of receivers used to decrypt the message.
     * @return verify result containing the parsed AuthorizationValidationRequest
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public RequestVerifyResult<AuthorizationValidationRequest> decryptAndVerifyAuthorizationValidationRequestMessage(EtsiTs103097DataEncryptedUnicast authorizationValidationRequestMessage,
                                                                                      Map<HashedId8, Certificate> certStore,
                                                                                      Map<HashedId8, Certificate> trustStore,
                                                                                      Map<HashedId8, Receiver> receiverStore)
            throws IllegalArgumentException, GeneralSecurityException, IOException {

        DecryptResult decryptedData = securedDataGenerator.decryptDataWithSecretKey(authorizationValidationRequestMessage,receiverStore);
        EtsiTs103097DataSigned outerSignature = new EtsiTs103097DataSigned(decryptedData.getData());
        SignedData outerSignedData = getSignedData(outerSignature, "AuthorizationValidationRequestMessage");

        EtsiTs102941Data requestData = parseEtsiTs102941Data(outerSignedData,"AuthorizationValidationRequestMessage",
                EtsiTs102941DataContent.EtsiTs102941DataContentChoices.authorizationValidationRequest);
        AuthorizationValidationRequest authorizationValidationRequest = requestData.getContent().getAuthorizationValidationRequest();

        verifySignedMessage(outerSignature,certStore,trustStore,"AuthorizationValidationRequestMessage");

        byte[] requestHash = genRequestHash(decryptedData.getData());
        return new RequestVerifyResult<>(outerSignedData.getSigner(),
                outerSignedData.getTbsData().getHeaderInfo(),authorizationValidationRequest, requestHash, decryptedData.getSecretKey());
    }

    /**
     * Method to generate a AuthorizationValidationResponseMessage according to ETSI TS 102 941 v 1.2.1.
     * <p>
     *     To create an <i>AuthorizationValidationResponseMessage</i>, an EA shall follow this process:
     *     <ul>
     *         <li>
     *             An <i>AuthorizationValidationResponse</i> structure is built, containing:
     *             <ul>
     *                 <li>the requestHash is the left-most 16 octets of the SHA256 digest of the
     *                   <i>EtsiTs103097DataSigned</i> structure received in the <i>AuthorizationValidationRequestMessage</i>
     *                 </li>
     *                 <li>a <i>responseCode</i> the response code applying to the request, based on EA internal
     *                 verification results;</li>
     *                 <li>if <i>responseCode</i> is 0, in the field <i>confirmedSubjectAttributes</i>, the attributes
     *                 the EA wishes to confirm, except for <i>certIssuePermissions</i> which is not allowed to be present;</li>
     *                 <li>if <i>responseCode</i> is different than 0, no component <i>confirmedSubjectAttributes</i></li>
     *             </ul>
     *         </li>
     *         <li>
     *             An <i>EtsiTs102941Data</i> structure is built, with:
     *             <ul>
     *                 <li>the version set to v1 (integer value set to 1);</li>
     *                 <li>the content set to the previous data structure(<i>AuthorizationValidationResponse</i>)</li>
     *             </ul>
     *         </li>
     *         <li>An <i>EtsiTs103097DataEncrypted</i> with:
     *         <ul>
     *             <li>the component <i>recipients</i> containing one instance of <i>RecipientInfo</i>
     *             of choice <i>pskRecipInfo</i>,which contains the HashedId8 of the symmetric key used by the ITS-S to
     *             encrypt the <i>AuthorizationRequest</i> message to which the response is built;
     *             </li>
     *             <li>
     *               the component <i>cipherText</i> containing the encrypted representation of the
     *               <i>EtsiTs103097DataSigned</i> structure;
     *             </li>
     *         </ul>
     *         </li>
     *         <li>
     *            An <i>EtsiTs103097Data-Signed</i> structure is built containing <i>hashId</i>,<i>tbsData</i>,
     *            <i>signer</i> and <i>signature</i>:
     *            <ul>
     *              <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3];</li>
     *              <li>in the <i>tbsData</i>:
     *              <ul>
     *                <li>the <i>payload</i> shall contain the previous <i>EtsiTs102941Data</i> structure.</li>
     *                <li>in the <i>headerInfo</i>:
     *                <ul>
     *                   <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *                   <li>the <i>generationTime</i> shall be present;</li>
     *                   <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *                </ul>
     *                </li>
     *              </ul>
     *              <li>the <i>signer</i> declared as <i>digest</i>, containing the HashedId8 of the EA certificate;</li>
     *              <li>the <i>signature</i> over <i>tbsData</i> computed using the EA private key corresponding to its
     *                publicVerificationKey found in the EA certificate.</li>
     *            </ul>
     *         </li>
     *     </ul>
     * </p>
     * @param generationTime the message generation time
     * @param authorizationValidationResponse the authorizationValidationResponse to include in the message.
     * @param signerCertificateChain the EA certificate chain used to signed.
     * @param signerPrivateKey the EA private key signing the message
     * @param preSharedKey the pre shared key used for encryption of messages between the parties. The secret key
     *                     should be the AES key used in the ECIES algorithm for the AuthorizationRequest.
     * @return encrypted and signed message containing AuthorizationValidationResponse.
     * @throws IllegalArgumentException if message contain invalid data
     * @throws IOException if problems occurred serializing the message data
     * @throws GeneralSecurityException if problems occurred encrypting the message.
     */
    public EtsiTs103097DataEncryptedUnicast genAuthorizationValidationResponseMessage(Time64 generationTime, AuthorizationValidationResponse authorizationValidationResponse,
                                                                            EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey,
                                                                            AlgorithmIndicator encryptionAlg, SecretKey preSharedKey) throws IllegalArgumentException, IOException, GeneralSecurityException {
        return genResponseMessage(generationTime, new EtsiTs102941DataContent(authorizationValidationResponse),signerCertificateChain,signerPrivateKey,encryptionAlg,preSharedKey);
    }

    /**
     * Method to decrypt and verify a AuthorizationValidationResponseMessage.
     *
     * @param authorizationValidationResponseMessage the complete encrypted authorizationValidationResponseMessage.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @param receiverStore map of receivers used to decrypt the message.
     * @return verify result containing the parsed AuthorizationValidationResponse
     * @throws IllegalArgumentException if message contained invalid data.
     * @throws GeneralSecurityException if problem occurred decrypting the data.
     * @throws SecurityException if problems occurred signing the data.
     * @throws IOException if problems occurred deserializing the data.
     */
    public VerifyResult<AuthorizationValidationResponse> decryptAndVerifyAuthorizationValidationResponseMessage(EtsiTs103097DataEncryptedUnicast authorizationValidationResponseMessage,
                                                                                      Map<HashedId8, Certificate> certStore,
                                                                                      Map<HashedId8, Certificate> trustStore,
                                                                                      Map<HashedId8, Receiver> receiverStore)
            throws IllegalArgumentException, GeneralSecurityException, IOException {

        byte[] decryptedData = securedDataGenerator.decryptData(authorizationValidationResponseMessage,receiverStore);
        EtsiTs103097DataSigned outerSignature = new EtsiTs103097DataSigned(decryptedData);
        SignedData outerSignedData = getSignedData(outerSignature, "AuthorizationValidationResponseMessage");

        EtsiTs102941Data requestData = parseEtsiTs102941Data(outerSignedData,"AuthorizationValidationResponseMessage",
                EtsiTs102941DataContent.EtsiTs102941DataContentChoices.authorizationValidationResponse);
        AuthorizationValidationResponse authorizationValidationResponse = requestData.getContent().getAuthorizationValidationResponse();

        verifySignedMessage(outerSignature,certStore,trustStore,"AuthorizationValidationResponseMessage");

        return new VerifyResult<>(outerSignedData.getSigner(),
                outerSignedData.getTbsData().getHeaderInfo(),authorizationValidationResponse);
    }

    /**
     * Common method to generate a response message for enrolment, authorization and authorization validation responses.
     * @param generationTime the message generation time
     * @param etsiTs102941DataContent the etsiTs102941DataContent to include in the message.
     * @param signerCertificateChain the certificate chain used to signed.
     * @param signerPrivateKey the private key signing the message
     * @param preSharedKey the pre shared key used for encryption of messages between the parties. The secret key
     *                     should be the AES key used in the ECIES algorithm for the AuthorizationRequest.
     * @return encrypted and signed message containing innerEcResponse.
     * @throws IllegalArgumentException if message contain invalid data
     * @throws IOException if problems occurred serializing the message data
     * @throws GeneralSecurityException if problems occurred encrypting the message.
     */
    protected EtsiTs103097DataEncryptedUnicast genResponseMessage(Time64 generationTime, EtsiTs102941DataContent etsiTs102941DataContent,
                                                                  EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey,
                                                                  AlgorithmIndicator encryptionAlg, SecretKey preSharedKey) throws IllegalArgumentException, IOException, GeneralSecurityException {
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(Version.V1,etsiTs102941DataContent);
        EtsiTs103097Data data = (EtsiTs103097Data) securedDataGenerator.genSignedData(headerInfo,etsiTs102941Data.getEncoded(), SecuredDataGenerator.SignerIdentifierType.HASH_ONLY,signerCertificateChain,signerPrivateKey);
        return (EtsiTs103097DataEncryptedUnicast) securedDataGenerator.encryptDataWithPresharedKey(encryptionAlg,data.getEncoded(),preSharedKey);
    }

    /**
     * Method to generate a CertificateRevocationListMessage according to ETSI TS 102 941 v 1.2.1.
     *
     * @param generationTime the time of the generation
     * @param toBeSignedCrl the toBeSignedCrl message to sign
     * @param signerCertificateChain the certificate chain to sign the list
     * @param signerPrivateKey the message signing private key.
     * @return a signed EtsiTs103097DataSigned data structure.
     * @throws IOException If problems occurred encoding the message.
     * @throws SignatureException if problems occurred generating the exception.
     */
    public EtsiTs103097DataSigned genCertificateRevocationListMessage(Time64 generationTime, ToBeSignedCrl toBeSignedCrl, EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IOException, SignatureException {
        return genSignedCTLMessage(generationTime,new EtsiTs102941DataContent(toBeSignedCrl), signerCertificateChain,signerPrivateKey);
    }

    /**
     * Method to verify a CertificateRevocationListMessage, only checks the signature of the message.
     * @param certificateRevocationListMessage the EtsiTs103097DataSigned CertificateRevocationListMessage to verify.
     * @param certStore a store of related certificate used to build chain.
     * @param trustStore the root ca trust store of trusted signers
     * @return a verification result of signer info, header info and ToBeSignedCrl content.
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    public VerifyResult<ToBeSignedCrl> verifyCertificateRevocationListMessage(EtsiTs103097DataSigned certificateRevocationListMessage,
                                                                              Map<HashedId8, Certificate> certStore,
                                                                              Map<HashedId8, Certificate> trustStore) throws IOException, SignatureException {
        VerifyResult<EtsiTs102941DataContent> verifyResult = verifyCTLMessage(certificateRevocationListMessage,certStore,trustStore, EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateRevocationList,"CertificateRevocationListMessage");
        return new VerifyResult<>(verifyResult.signerIdentifier,verifyResult.headerInfo,verifyResult.value.getToBeSignedCrl());
    }

    /**
     * Method to generate a TlmCertificateTrustListMessage according to ETSI TS 102 941 v 1.2.1.
     *
     * @param generationTime the time of the generation
     * @param toBeSignedTlmCtl the ToBeSignedTlmCtl message to sign
     * @param signerCertificateChain the certificate chain to sign the list
     * @param signerPrivateKey the message signing private key.
     * @return a signed EtsiTs103097DataSigned data structure.
     * @throws IOException If problems occurred encoding the message.
     * @throws SignatureException if problems occurred generating the exception.
     */
    public EtsiTs103097DataSigned genTlmCertificateTrustListMessage(Time64 generationTime, ToBeSignedTlmCtl toBeSignedTlmCtl, EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IOException, SignatureException {
        return genSignedCTLMessage(generationTime,new EtsiTs102941DataContent(toBeSignedTlmCtl), signerCertificateChain,signerPrivateKey);
    }

    /**
     * Method to verify a TlmCertificateTrustListMessage, only checks the signature of the message.
     * @param tlmCertificateTrustListMessage the EtsiTs103097DataSigned TlmCertificateTrustListMessage to verify.
     * @param certStore a store of related certificate used to build chain.
     * @param trustStore the root ca trust store of trusted signers
     * @return a verification result of signer info, header info and ToBeSignedCrl content.
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    public VerifyResult<ToBeSignedTlmCtl> verifyTlmCertificateTrustListMessage(EtsiTs103097DataSigned tlmCertificateTrustListMessage,
                                                                              Map<HashedId8, Certificate> certStore,
                                                                              Map<HashedId8, Certificate> trustStore) throws IOException, SignatureException {
        VerifyResult<EtsiTs102941DataContent> verifyResult = verifyCTLMessage(tlmCertificateTrustListMessage,certStore,trustStore, EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateTrustListTlm,"TlmCertificateTrustListMessage");
        return new VerifyResult<>(verifyResult.signerIdentifier,verifyResult.headerInfo,verifyResult.value.getToBeSignedTlmCtl());
    }

    /**
     * Method to generate a RcaCertificateTrustListMessage according to ETSI TS 102 941 v 1.2.1.
     *
     * @param generationTime the time of the generation
     * @param toBeSignedRcaCtl the toBeSignedRcaCtl message to sign
     * @param signerCertificateChain the certificate chain to sign the list
     * @param signerPrivateKey the message signing private key.
     * @return a signed EtsiTs103097DataSigned data structure.
     * @throws IOException If problems occurred encoding the message.
     * @throws SignatureException if problems occurred generating the exception.
     */
    public EtsiTs103097DataSigned genRcaCertificateTrustListMessage(Time64 generationTime, ToBeSignedRcaCtl toBeSignedRcaCtl, EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IOException, SignatureException {
        return genSignedCTLMessage(generationTime,new EtsiTs102941DataContent(toBeSignedRcaCtl), signerCertificateChain,signerPrivateKey);
    }

    /**
     * Method to verify a RcaCertificateTrustListMessage, only checks the signature of the message.
     * @param rcaCertificateTrustListMessage the EtsiTs103097DataSigned RcaCertificateTrustListMessage to verify.
     * @param certStore a store of related certificate used to build chain.
     * @param trustStore the root ca trust store of trusted signers
     * @return a verification result of signer info, header info and ToBeSignedCrl content.
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    public VerifyResult<ToBeSignedRcaCtl> verifyRcaCertificateTrustListMessage(EtsiTs103097DataSigned rcaCertificateTrustListMessage,
                                                                               Map<HashedId8, Certificate> certStore,
                                                                               Map<HashedId8, Certificate> trustStore) throws IOException, SignatureException {
        VerifyResult<EtsiTs102941DataContent> verifyResult = verifyCTLMessage(rcaCertificateTrustListMessage,certStore,trustStore, EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateTrustListRca,"RcaCertificateTrustListMessage");
        return new VerifyResult<>(verifyResult.signerIdentifier,verifyResult.headerInfo,verifyResult.value.getToBeSignedRcaCtl());
    }


    /**
     * Method to generate a CaCertificateRequestMessage according to section 6.2.1 in ETSI TS 102 941 v 1.2.1
     * <p>
     *     For the initial application to the RCA, an EA or AA shall follow this process to create a CaCertificateRequestMessage:
     *     <ul>
     *         <li>An ECC private key is randomly generated, the corresponding public key (<i>verificationKey</i>) is provided
     *         to be included in the CaCertificateRequest.</li>
     *         <li>An ECC encryption private key is randomly generated, the corresponding public key (<i>encryptionKey</i>)
     *         is provided to be included in the CACertificateRequest.</li>
     *         <li>
     *             An EtsiTs102941Data structure is built, containing:
     *             <ul>
     *                 <li><i>version</i> is set to v1 (integer value set to 1);</li>
     *                 <li>A <i>CaCertificateRequest</i> is built with:</li>
     *                 <ul>
     *                     <li>publicKeys shall contain verification_key and encryption_key;</li>
     *                     <li>requestedSubjectAttributes shall contain the requested certificates attributes as specified in ETSI
     *                     TS 103 097 [3], clause 7.2.4.</li>
     *                 </ul>
     *             </ul>
     *         </li>
     *         <li>
     *             An EtsiTs103097Data-Signed structure is built, containing: hashId, tbsData, signer and signature:
     *             <ul>
     *                 <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103
     *                 097 [3].</li>
     *                 <li>in <i>tbsData</i>:
     *                 <ul>
     *                     <li>the <i>payload</i> shall contain the previous <i>EtsiTs102941Data</i> structure;</li>
     *                     <li>in the <i>headerInfo</i>:
     *                     <ul>
     *                         <li>the <i>psid</i> shall be set to "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *                         <li>the <i>generationTime</i> shall be present;</li>
     *                         <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *                     </ul>
     *                     </li>
     *                 </ul>
     *                 </li>
     *             </ul>
     *         </li>
     *         <li>the <i>signer</i> is set to 'self'.</li>
     *         <li>the <i>signature</i> over the <i>tbsData</i> computed using the private key corresponding to the new
     *         <i>verificationKey</i> to be certified (i.e. the request is self-signed).</li>
     *     </ul>
     * </p>
     *
     * @param generationTime the time of the generation
     * @param caCertificateRequest the caCertificateRequest
     * @param signerPublicKey the message signing public key.
     * @param signerPrivateKey the message signing private key.
     * @return a signed EtsiTs103097DataSigned data structure.
     * @throws IOException If problems occurred encoding the message.
     * @throws SignatureException if problems occurred generating the exception.
     */
    public EtsiTs103097DataSigned genCaCertificateRequestMessage(Time64 generationTime, CaCertificateRequest caCertificateRequest, PublicKey signerPublicKey, PrivateKey signerPrivateKey) throws IOException, SignatureException {
        EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(Version.V1, new EtsiTs102941DataContent(caCertificateRequest));
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        return securedDataGenerator.genEtsiTs103097DataSigned(headerInfo, etsiTs102941Data.getEncoded(),signerPublicKey,signerPrivateKey);
    }


    /**
     * For the re-keying application to the RCA, an EA or AA shall follow this process to create a
     * CaCertificateRekeyingMessage.
     *
     * <p>
     *     <ul>
     *         <li>An EtsiTs103097DataSigned structure is built, containing: hashId, tbsData, signer and signature
     *         <ul>
     *             <li>the <i>hashId</i> shall indicate the hash algorithm to be used as specified in ETSI TS 103 097 [3].</li>
     *             <li>in the <i>tbsData</i>:
     *             <ul>
     *                 <li>the payload shall contain theprevious <i>CaCertificateRequestMessage</i> structure;</li>
     *                 <li>In the <i>headerInfo</i>:
     *                     <ul>
     *                         <li>the <i>psid</i> shall be set "secured certificate request" as assigned in ETSI TS 102 965 [19];</li>
     *                         <li>the <i>generationTime</i> shall be present;</li>
     *                         <li>all other components of the component <i>tbsdata.headerInfo</i> not used and absent;</li>
     *                     </ul>
     *                 </li>
     *             </ul>
     *             <li>the <i>signer</i> declared as a <i>digest</i> containing the hashedId8 of the EA or AA certificate;</li>
     *             <li>the <i>signature</i> over <i>tbsData</i> computed using the currently valid private key corresponding to the
     * AA or EA certificate (outer signature).</li>
     *             </li>
     *         </ul>
     *         </li>
     *     </ul>
     * </p>
     *
     * @param generationTime the time of the generation
     * @param caCertificateRequest the caCertificateRequest
     * @param oldCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
     * must be in the order of end entity certificate at position 0 and trust anchor last in array.
     * @param oldSignerPrivateKey old signing private key
     * @param newSignerPublicKey new public key that should be renewed.
     * @param newSignerPrivateKey new private key that should be renewed.
     * @return a signed EtsiTs103097DataSigned data structure.
     * @throws IOException If problems occurred encoding the message.
     * @throws SignatureException if problems occurred generating the exception.
     */
    public EtsiTs103097DataSigned genCaCertificateRekeyingMessage(Time64 generationTime, CaCertificateRequest caCertificateRequest,
                                                          EtsiTs103097Certificate[] oldCertificateChain, PrivateKey oldSignerPrivateKey,
                                                          PublicKey newSignerPublicKey, PrivateKey newSignerPrivateKey) throws IOException, SignatureException {
        EtsiTs103097DataSigned innerSignature = genCaCertificateRequestMessage(generationTime,caCertificateRequest, newSignerPublicKey,  newSignerPrivateKey);
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        return securedDataGenerator.genEtsiTs103097DataSigned(headerInfo, innerSignature.getEncoded(), SecuredDataGenerator.SignerIdentifierType.HASH_ONLY,oldCertificateChain,oldSignerPrivateKey);
    }


    /**
     * Method to verify the signature and parse a CACertificateRequestMessage. This method verifies the signature only
     * not the header values.
     *
     * @param caCertificateRequestMessage the message to verify and parse.
     * @return true if data structure signature verifies.
     * @return a verify result with the decoded CaCertificateRequest and signer identifier and header info.
     * @throws IllegalArgumentException if message data contained invalid data.
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    public VerifyResult<CaCertificateRequest> verifyCACertificateRequestMessage(EtsiTs103097DataSigned caCertificateRequestMessage) throws IllegalArgumentException, SignatureException, IOException {
        SignedData signedData = getSignedData(caCertificateRequestMessage,"CACertificateRequestMessage");
        EtsiTs102941Data requestData = parseEtsiTs102941Data(signedData,"CACertificateRequestMessage", EtsiTs102941DataContent.EtsiTs102941DataContentChoices.caCertificateRequest);
        CaCertificateRequest caCertificateRequest = requestData.getContent().getCaCertificateRequest();
        PublicKey signPublicKey = genPublicKey(caCertificateRequest.getPublicKeys().getVerificationKey(),"CACertificateRequestMessage");

        verifySelfSignedMessage(caCertificateRequestMessage,signPublicKey,"CACertificateRequestMessage");

        return new VerifyResult<>(signedData.getSigner(),getHeaderInfo(caCertificateRequestMessage),caCertificateRequest);
    }

    /**
     * Method to verify the signature and parse a CACertificateRekeyingMessage. This method verifies the signature only
     * not the header values.
     *
     * @param caCertificateRekeyingMessage the message to verify and parse.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @return a verify result with the decoded CaCertificateRequest and signer identifier and header info.
     * @throws IllegalArgumentException if message data contained invalid data.
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    public VerifyResult<CaCertificateRequest> verifyCACertificateRekeyingMessage(EtsiTs103097DataSigned caCertificateRekeyingMessage,Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore) throws IllegalArgumentException, SignatureException, IOException {
        verifySignedMessage(caCertificateRekeyingMessage,certStore,trustStore,"CACertificateRekeyingMessage");
        SignedData signedData = getSignedData(caCertificateRekeyingMessage,"CACertificateRekeyingMessage");

        Ieee1609Dot2Data unsecuredData = signedData.getTbsData().getPayload().getData();
        if(unsecuredData.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.unsecuredData){
            throw new IllegalArgumentException("Invalid encoding in CACertificateRekeyingMessage, signed data should contain payload of unsecuredData.");
        }
        Opaque opaque = (Opaque) unsecuredData.getContent().getValue();
        EtsiTs103097DataSigned innerSignedMessage = new EtsiTs103097DataSigned(opaque.getData());
        VerifyResult<CaCertificateRequest> innerResult = verifyCACertificateRequestMessage(innerSignedMessage);
        return new VerifyResult<>(signedData.getSigner(),getHeaderInfo(caCertificateRekeyingMessage),innerResult.getValue());
    }


    /**
     * Generates a default header with ITS Id SecuredCertificateRequestService and generationTime set.
     * @param generationTime the generation time to set in header.
     * @return an newly created HeaderInfo
     */
    protected HeaderInfo genHeaderInfo(Time64 generationTime){
        return new HeaderInfo(AvailableITSAID.SecuredCertificateRequestService,generationTime,null,null,null,null,null,null,null);
    }

    /**
     * Method to retrieve a header info from a
     * @param etsiTs103097Data the EtsiTs103097Data to parse header info from.
     * @return the related header info.
     * @throws IllegalArgumentException if given EtsiTs103097Data is not a signedData
     */
    public HeaderInfo getHeaderInfo(EtsiTs103097Data etsiTs103097Data) throws IllegalArgumentException{
        if(etsiTs103097Data.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData){
            throw new IllegalArgumentException("Illegal argument to getHeaderInfo, EtsiTs103097Data must be of type signedData.");
        }
        SignedData signedData = (SignedData) etsiTs103097Data.getContent().getValue();
        return signedData.getTbsData().getHeaderInfo();
    }


    /**
     * Help method to generate a PublicKeys data structure.
     * @param alg the signing algorithm used
     * @param signPk the signing public key.
     * @param symmAlgorithm the symmetric algorithm used. null if no encryption key should be set.
     * @param encAlg the encryption algorithm used. null if no encryption key should be set.
     * @param encPk the encryption public key used. null if no encryption key should be set.
     * @return a newly generated PublicKeys data structure.
     */
    public PublicKeys genPublicKeys(AlgorithmIndicator alg, PublicKey signPk, SymmAlgorithm symmAlgorithm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg, PublicKey encPk ){
        PublicVerificationKey publicVerificationKey = genPublicVerificationKey(alg,signPk);
        if(encPk == null) {
            return new PublicKeys(publicVerificationKey, null);
        }
        assert symmAlgorithm != null;
        assert encAlg != null;
        PublicEncryptionKey publicEncryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encAlg, convertToPoint(encAlg, encPk)));
        return new PublicKeys(publicVerificationKey, publicEncryptionKey);
    }

    /**
     * Method to build a cert store map of HashedId8 to Certificate from an array of certificates.
     * @param certificates the array of certificate to build store of.
     * @return a map of HashedId8 to certificate.
     */
    public Map<HashedId8, Certificate> buildCertStore(EtsiTs103097Certificate[] certificates) throws IOException, NoSuchAlgorithmException {
        return securedDataGenerator.buildCertStore(certificates);
    }

    /**
     * Method to build a cert store map of HashedId8 to Certificate from a collection of certificates.
     * @param certificates the collection of certificate to build store of.
     * @return a map of HashedId8 to certificate.
     */
    public Map<HashedId8, Certificate> buildCertStore(List<Certificate> certificates) throws IOException, NoSuchAlgorithmException {
        return securedDataGenerator.buildCertStore(certificates);
    }

    /**
     * Method to build a store of receiver in order of a hashedId8 -> Receiver
     *
     * @param receivers collection of receivers to build map of.
     * @return a map of hashedId8 -> receiver
     */
    public Map<HashedId8, Receiver> buildRecieverStore(Collection<Receiver> receivers) throws IllegalArgumentException, IOException, GeneralSecurityException{
        return securedDataGenerator.buildRecieverStore(receivers);
    }

    /**
     * Method to build a store of receiver in order of a hashedId8 -> Receiver
     *
     * @param receivers array of receivers to build map of.
     * @return a map of hashedId8 -> receiver
     */
    public Map<HashedId8, Receiver> buildRecieverStore(Receiver[] receivers) throws IllegalArgumentException, IOException, GeneralSecurityException{
        return securedDataGenerator.buildRecieverStore(receivers);
    }

    /**
     * Common help method to generate a signed only message.
     * @param generationTime the time of the generation
     * @param etsiTs102941DataContent the to be signed message data.
     * @param signerCertificateChain the certificate chain if signer certificate.
     * @param signerPrivateKey the message signing private key.
     * @return a signed EtsiTs103097DataSigned data structure.
     * @throws IOException If problems occurred encoding the message.
     * @throws SignatureException if problems occurred generating the exception.
     */
    public EtsiTs103097DataSigned genSignedCTLMessage(Time64 generationTime, EtsiTs102941DataContent etsiTs102941DataContent, EtsiTs103097Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IOException, SignatureException {
        EtsiTs102941Data etsiTs102941Data = new EtsiTs102941Data(Version.V1, etsiTs102941DataContent);
        HeaderInfo headerInfo = genHeaderInfo(generationTime);
        return securedDataGenerator.genEtsiTs103097DataSigned(headerInfo, etsiTs102941Data.getEncoded(), SecuredDataGenerator.SignerIdentifierType.SIGNER_CERTIFICATE,signerCertificateChain,signerPrivateKey);
    }

    /**
     * Common help method to verify a CTL and CRL Message
     * @param ctlMessage the CTL or CRL message to verify, only checks signature of message
     * @param certStore a store of related certificate used to build chain.
     * @param trustStore the root ca trust store of trusted signers
     * @param expectedType the expected EtsiTs102941DataContent type.
     * @param messageName the message name
     * @return a verification result of signer info, header info and EtsiTs102941DataContent.
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    public VerifyResult<EtsiTs102941DataContent> verifyCTLMessage(EtsiTs103097DataSigned ctlMessage, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore, EtsiTs102941DataContent.EtsiTs102941DataContentChoices expectedType,String messageName) throws IOException, SignatureException {
        SignedData signedData = getSignedData(ctlMessage,messageName);
        verifySignedMessage(ctlMessage,certStore,trustStore,messageName);
        EtsiTs102941Data data = parseEtsiTs102941Data(signedData,messageName,expectedType);
        return new VerifyResult<>(signedData.getSigner(),signedData.getTbsData().getHeaderInfo(),data.getContent());
    }

    /**
     * Help method to generate a PublicVerificationKey data structure
     */
    protected PublicVerificationKey genPublicVerificationKey(AlgorithmIndicator alg, PublicKey pk) {
        return new PublicVerificationKey(BaseCertGenerator.getPublicVerificationAlgorithm(alg),convertToPoint(alg,pk));
    }

    /**
     * Help method to convert a public verification key to public key.
     */
    protected PublicKey genPublicKey(PublicVerificationKey publicVerificationKey, String messageName) throws IllegalArgumentException{
        try {
            return (PublicKey) securedDataGenerator.getCryptoManager().decodeEccPoint(publicVerificationKey.getType(), (EccCurvePoint) publicVerificationKey.getValue());
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid encoding in " + messageName + ", Public verification key was contained invalid ecc point: " + e.getMessage(),e);
        }
    }

    /**
     * Method to parse SignedData from a EtsiTs103097DataSigned structure.
     * @param etsiTs103097DataSigned the EtsiTs103097DataSigned structure.
     * @param messageName the name of the message used in error message.
     * @return the SignedData structure.
     */
    protected SignedData getSignedData(EtsiTs103097Data etsiTs103097DataSigned, String messageName){
        if(etsiTs103097DataSigned.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData){
            throw new IllegalArgumentException("Invalid encoding in " + messageName + ", message type must be signed data");
        }
        SignedData signedData = (SignedData) etsiTs103097DataSigned.getContent().getValue();
        if(signedData.getTbsData().getPayload().getData() == null){
            throw new IllegalArgumentException("Invalid encoding in " + messageName + " SignedData, data field cannot be null");
        }
        return signedData;
    }

    protected EtsiTs102941Data parseEtsiTs102941Data(SignedData signedData, String messageName, EtsiTs102941DataContent.EtsiTs102941DataContentChoices expectedType) throws IOException {
        Ieee1609Dot2Data unsecuredData = signedData.getTbsData().getPayload().getData();
        if(unsecuredData.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.unsecuredData){
            throw new IllegalArgumentException("Invalid encoding in "+ messageName +", signed data should contain payload of unsecuredData.");
        }
        Opaque opaque = (Opaque) unsecuredData.getContent().getValue();
        EtsiTs102941Data requestData = new EtsiTs102941Data(opaque.getData());
        if(requestData.getContent().getType() != expectedType){
            throw new IllegalArgumentException("Invalid encoding in "+ messageName +", signed EtsiTs102941Data should be of type " + expectedType + ".");
        }
        return requestData;
    }

    /**
     * Help method to verify a self signed message.
     * @param etsiTs103097DataSigned the message to verify.
     * @param signPublicKey the public key that signed the message.
     * @param messageName the message name
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    protected void verifySelfSignedMessage(EtsiTs103097DataSigned etsiTs103097DataSigned, PublicKey signPublicKey, String messageName) throws SignatureException, IOException {
        if(!securedDataGenerator.verifySignedData(etsiTs103097DataSigned, signPublicKey)){
            throw new SignatureException("Invalid signature of "+ messageName +".");
        }
    }

    /**
     * Help method to verify a signed message.
     * @param etsiTs103097DataSigned the message to verify.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @return true if data structure signature verifies.
     * @param messageName the message name
     * @throws SignatureException if signature didn't verify.
     * @throws IOException if problems occurred de-serializing the data structure.
     */
    protected void verifySignedMessage(EtsiTs103097DataSigned etsiTs103097DataSigned, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore, String messageName) throws SignatureException, IOException {
        if(!securedDataGenerator.verifySignedData(etsiTs103097DataSigned,certStore,trustStore)){
            throw new SignatureException("Invalid signature of "+ messageName +".");
        }
    }

    /**
     * Help method to convert a public key to EccP256CurvePoint using given compression.
     */
    protected COERChoice convertToPoint(AlgorithmIndicator alg, PublicKey pk) throws IllegalArgumentException{
        return BaseCertGenerator.convertToPoint(alg, pk, securedDataGenerator.getCryptoManager(), useUncompressed);
    }

    /**
     * Help method retrieving the recipient algorithm from the related recipient certificate.
     * @param recipient the recipient certificate
     * @return the related encryption algorithm
     * @throws IllegalArgumentException if recipient certificate didn't contain any encryptionKey.
     */
    protected BasePublicEncryptionKey.BasePublicEncryptionKeyChoices getRecipientAlgorithm(Certificate recipient) throws IllegalArgumentException{
        if(recipient.getToBeSigned().getEncryptionKey() == null ){
            throw new IllegalArgumentException("Invalid encryption recipient certificate, certificate contained no encryption key.");
        }
        return recipient.getToBeSigned().getEncryptionKey().getPublicKey().getType();
    }

    /**
     * Help method to digest data using SHA156 and returning the 16 leftmost bytes.
     * @param data the data to calculcate the request hash for.
     * @return the generated request hash.
     */
    protected byte[] genRequestHash(byte[] data) throws NoSuchAlgorithmException {
        byte[] digest = securedDataGenerator.getCryptoManager().digest(data,HashAlgorithm.sha256);
        return Arrays.copyOf(digest,16);
    }
}
