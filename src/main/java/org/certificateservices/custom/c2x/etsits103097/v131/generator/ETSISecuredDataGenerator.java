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
package org.certificateservices.custom.c2x.etsits103097.v131.generator;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedExternalPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.Recipient;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Generator class generating secure data messages defined in ETSI TS 103 097 v 1.3.1 standard.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class ETSISecuredDataGenerator extends SecuredDataGenerator {

    /**
     * Main constructor.
     *
     * @param version       version if Ieee1609Dot2Data to generate.
     * @param cryptoManager the related crypto manager
     * @param hashAlgorithm the related hash algorithm used in messages
     * @param signAlgorithm the related sign algorithm used in messages.
     * @throws SignatureException if internal problems occurred initializing the generator.
     */
    public ETSISecuredDataGenerator(int version, Ieee1609Dot2CryptoManager cryptoManager, HashAlgorithm hashAlgorithm, Signature.SignatureChoices signAlgorithm) throws SignatureException {
        super(version, cryptoManager, hashAlgorithm, signAlgorithm);
    }


    /**
     * Method to generate a CA Message according to profile.
     *
     * @param generationTime the generation time of the message. (required)
     * @param inlineP2pcdRequest the sequence of hashes in inlindP2pcdRequest header info.
     * @param requestedCertificate the requestedCertificate header info. (Optional)
     * @param message the encoded DENM message.
     * @param signerCertificate the certificate signing the message.
     * @param signerPrivateKey private key of signer.
     * @return a newly generated signed CA Message.
     * @throws IllegalArgumentException if fault was discovered in supplied parameters.
     * @throws SignatureException if internal problems occurred generating the signature.
     * @throws IOException if IO exception occurred communicating with underlying systems.
     */
    public EtsiTs103097DataSigned genCAMessage(Time64 generationTime, SequenceOfHashedId3 inlineP2pcdRequest, Certificate requestedCertificate, byte[] message, SignerIdentifierType signerIdentifierType,Certificate signerCertificate, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
        if(signerIdentifierType == SignerIdentifierType.CERT_CHAIN){
            throw new IllegalArgumentException("Unsupported signerIdentifierType for CA Message: " + signerIdentifierType);
        }
        HeaderInfo headerInfo =  new HeaderInfo(AvailableITSAID.CABasicService,generationTime,null,null,null,null,null,inlineP2pcdRequest,requestedCertificate);
        return genEtsiTs103097DataSigned(headerInfo,message,signerIdentifierType,new Certificate[]{signerCertificate},signerPrivateKey);
    }



    /**
     * Method to generate a DEN Message according to profile.
     *
     * @param generationTime the generation time of the message.
     * @param generationLocation the generation location of the message.
     * @param message the encoded DENM message.
     * @param signerCertificate the certificate signing the message.
     * @param signerPrivateKey private key of signer.
     * @return
     * @throws IllegalArgumentException if fault was discovered in supplied parameters.
     * @throws SignatureException if internal problems occurred generating the signature.
     * @throws IOException if IO exception occurred communicating with underlying systems.
     */
    public EtsiTs103097DataSigned genDENMessage(Time64 generationTime, ThreeDLocation generationLocation, byte[] message, Certificate signerCertificate, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
        HeaderInfo headerInfo =  new HeaderInfo(AvailableITSAID.DENBasicService,generationTime,null,generationLocation,null,null,null,null,null);
        return genEtsiTs103097DataSigned(headerInfo,message,SignerIdentifierType.SIGNER_CERTIFICATE,new Certificate[]{signerCertificate},signerPrivateKey);
    }

    /**
     * Method to generate a general Signed EtsiTs103097DataSigned containing an unsecured inner data.
     *
     * @param headerInfo the header information data to include.
     * @param message the message data to sign.
     * @param signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
     * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
     * must be in the order of end entity certificate at position 0 and trust anchor last in array.
     * @param signerPrivateKey private key of signer.
     *
     * @throws IllegalArgumentException if fault was discovered in supplied parameters.
     * @throws SignatureException if internal problems occurred generating the signature.
     * @throws IOException if IO exception occurred communicating with underlying systems.
     */
    public EtsiTs103097DataSigned genEtsiTs103097DataSigned(HeaderInfo headerInfo, byte[] message, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
        return (EtsiTs103097DataSigned) super.genSignedData(headerInfo,message, signerIdentifierType,signerCertificateChain,signerPrivateKey);
    }

    /**
     * Method to generate a general Signed EtsiTs103097DataSigned containing an unsecured inner data with signer type as
     * self.
     *
     * @param headerInfo the header information data to include.
     * @param message the message data to sign.
     * @param signerPublicKey public key of the self signer of a message.
     * @param signerPrivateKey private key of signer.
     *
     * @throws IllegalArgumentException if fault was discovered in supplied parameters.
     * @throws SignatureException if internal problems occurred generating the signature.
     * @throws IOException if IO exception occurred communicating with underlying systems.
     */
    public EtsiTs103097DataSigned genEtsiTs103097DataSigned(HeaderInfo headerInfo, byte[] message, PublicKey signerPublicKey, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
        return (EtsiTs103097DataSigned) super.genSignedData(headerInfo, message, signerPublicKey, signerPrivateKey);
    }

    /**
     * Method to generate a general Signed EtsiTs103097DataSignedExternalPayload containing an unsecured inner data.
     *
     * @param headerInfo the header information data to include.
     * @param message the message data to sign.
     * @param signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
     * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
     * must be in the order of end entity certificate at position 0 and trust anchor last in array.
     * @param signerPrivateKey private key of signer.
     *
     * @throws IllegalArgumentException if fault was discovered in supplied parameters.
     * @throws SignatureException if internal problems occurred generating the signature.
     * @throws IOException if IO exception occurred communicating with underlying systems.
     */
    public EtsiTs103097DataSignedExternalPayload genEtsiTs103097DataSignedExternalPayload(HeaderInfo headerInfo, byte[] message, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
        return (EtsiTs103097DataSignedExternalPayload) super.genReferencedSignedData(headerInfo,message, signerIdentifierType,signerCertificateChain,signerPrivateKey);
    }

    /**
     * Method to generate a new EtsiTs103097Data with Encrypted profile.
     *
     * @param alg algorithm indicating which symmetric and depending on encryption method which asymmetric algorithm to use.
     * @param data the data to encrypt
     * @param recipients a list of recipients, all recipients should be a Recipient implementation and be of the same type.
     *
     * @return an encrypted Ieee1609Dot2Data structure.
     * @throws IllegalArgumentException if one of the argument was invalid.
     * @throws GeneralSecurityException if internal problems occurred encrypting the data.
     * @throws IOException if communication problems occurred when encrypting the data.
     */
    public EncryptResult genEtsiTs103097DataEncrypted(AlgorithmIndicator alg, byte[] data, Recipient[] recipients) throws IllegalArgumentException, GeneralSecurityException, IOException{
        return super.encryptData(alg,data,recipients);
    }

    /**
     * Method to generate a new EtsiTs103097Data with SignedAndEncrypted profile.
     *
     * @param headerInfo the header information data to include.
     * @param message the data to sign and encrypt
     * @param signerIdentifierType signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
     * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
     * must be in the order of end entity certificate at position 0 and trust anchor last in array.
     * @param signerPrivateKey  private key of signer.
     * @param encAlg algorithm indicating which symmetric and depending on encryption method which asymmetric algorithm to use.
     * @param recipients  a list of recipients, all receiptients should be a Recipient implementation and be of the same type.
     * @return a signed and then encrypted Ieee1609Dot2Data structure.
     *
     * @throws IllegalArgumentException if fault was discovered in supplied parameters.
     * @throws SignatureException if internal problems occurred generating the signature.
     * @throws IOException if IO exception occurred communicating with underlying systems.
     * @throws GeneralSecurityException if internal problems occurred encrypting the data.
     */
    public EncryptResult genEtsiTs103097DataSignedAndEncrypted(HeaderInfo headerInfo, byte[] message, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey, AlgorithmIndicator encAlg,Recipient[] recipients) throws IllegalArgumentException, SignatureException, GeneralSecurityException, IOException{
        return super.signAndEncryptData(headerInfo,message,signerIdentifierType,signerCertificateChain,signerPrivateKey,encAlg,recipients);
    }

    @Override
    protected Ieee1609Dot2Data newEncryptedDataStructure(byte[] encodedData) throws IOException {
        return new EtsiTs103097DataEncrypted(encodedData);
    }

    @Override
    protected Ieee1609Dot2Data newEncryptedDataStructure(int version, Ieee1609Dot2Content content) throws IOException {
        return new EtsiTs103097DataEncrypted(version,content);
    }

    /**
     * Overridable method that creates a new signed Ieee1609Dot2Data structure
     *
     * @param version   version of message.
     * @param content   the data content.
     * @param enveloped if signature data is included or external reference is used.
     */
    @Override
    protected Ieee1609Dot2Data newSignedDataStructure(int version, Ieee1609Dot2Content content, boolean enveloped) {
        if(enveloped){
            return new EtsiTs103097DataSigned(version,content);
        }
        return new EtsiTs103097DataSignedExternalPayload(version,content);
    }
}
