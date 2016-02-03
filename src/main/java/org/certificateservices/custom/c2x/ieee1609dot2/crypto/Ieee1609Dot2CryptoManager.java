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
package org.certificateservices.custom.c2x.ieee1609dot2.crypto;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.ToBeSignedCertificate;


/**
 * Interface defining methods used by c2x specific cryptographic methods. 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public interface Ieee1609Dot2CryptoManager extends CryptoManager {
	
//
//	/**
//	 * Message to encrypt a securedmessage to a list of recepients.
//	 * 
//	 * This method will encrypt all payloads with payload type 'encrypted'. To construct an encrypted message
//	 * you should first generate the message and add payloads with encrypted type and cleartext data, then call this method which will
//	 * replace the data with encrypted equivalent.
//	 * 
//	 * @param secureMessage the secure message to encrypt.
//	 * @param encryptionAlg the encryption algorithm to use.
//	 * @param receipients a list of certificates of recipients, must have a encryption key specified in each certificate.
//	 * @return A SecureMessage with it's payload encrypted.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid, such as one of 
//	 *         the recipients certificates didn't have an encryption key..
//	 * @throws GeneralSecurityException if internal problems occurred encrypting the message.
//	 * @throws IOException if communication problems occurred with underlying components
//	 */
//	public SecuredMessage encryptSecureMessage(SecuredMessage secureMessage, PublicKeyAlgorithm encryptionAlg, List<Certificate> receipients) throws  IllegalArgumentException, GeneralSecurityException, IOException;
//	
//	/**
//	 * Message to decrypt a secured message, i.e.A all payloads with payload type 'encrypted'. 
//	 * 
//	 * @param secureMessage the secure message to decrypt.
//	 * @param receiverCertificate the certificate for the private key used for decryption.
//	 * @param receiverKey the private key used to decrypt the message.
//	 * @return A SecureMessage with it's payload in cleartext.
//	 * 
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid, such as one of 
//	 *         the recipients certificates didn't have an encryption key..
//	 * @throws GeneralSecurityException if internal problems occurred decrypting the message.
//	 * @throws IOException if communication problems occurred with underlying components
//	 */
//	public SecuredMessage decryptSecureMessage(SecuredMessage secureMessage, Certificate receiverCertificate, PrivateKey receiverKey) throws  IllegalArgumentException, GeneralSecurityException, IOException;
//	
//
//	/**
//	 * Method to sign a secured message using the given algorithm and private key and returns the same message with
//	 * an attached signature according to the ITS specification with EccPointType x_coordinate_only containing the R value.
//	 * <p>
//	 * <b>Important: This method will add signed info header to the message automatically and it doesn't need to be added manually.</b>
//	 * 
//	 * @param secureMessage the message data to sign.
//	 * @param signerCertificate the certificate used when signing.
//	 * @param signerInfoType indicates the type of SignerInfo inserted into generated messages, supported values are:
//	 * certificate_digest_with_ecdsap256 or certificate.
//	 * @param alg the public key algorithm scheme to use.
//	 * @param privateKey the private key used to sign the message.
//	 * @return the message ITS Signature data structure containing the generated signature attached.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws SignatureException if internal problems occurred generating the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	SecuredMessage signSecureMessage(SecuredMessage secureMessage, Certificate signerCertificate, SignerInfoType signerInfoType, PublicKeyAlgorithm alg,
//				PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException;
//	
	

	/**
	 * Method used to sign the a message data according to the IEEE specification with EccPointType x_coordinate_only containing the R value.
	 * 
	 * @param message the message data to sign.
	 * @param alg the public key algorithm scheme to use.
	 * @param privateKey the private key used to sign the message.
	 * @param signingCert the signer or null if self signed.
	 * @return a IEEE 1609.2 Signature data structure containing the generated signature.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	Signature signMessage(byte[] message, AlgorithmIndicator alg, PrivateKey privateKey, CertificateType certType, Certificate signingCert) throws IllegalArgumentException, SignatureException, IOException;
	
	/**
	 * Method used to sign the a digest of message according to the IEEE specification with EccPointType x_coordinate_only containing the R value.
	 * 
	 * @param digest the hash data to sign.
	 * @param alg the public key algorithm scheme to use.
	 * @param privateKey the private key used to sign the message.
	 * @return a IEEE 1609.2 Signature data structure containing the generated signature.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	Signature signMessageDigest(byte[] message, AlgorithmIndicator alg, PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException;
		
//	
//	/**
//	 * Method to sign and encrypt a secured message using the given algorithm and private keys and returns another message with
//	 * an attached signature according to the ITS specification with EccPointType x_coordinate_only containing the R value.
//	 * <p>
//	 * This method will only encrypt payload with type signed_and_encrypted
//	 * <p>
//	 * <b>Important: This method will add signing and encryption header to the message automatically and it doesn't need to be added manually.</b>
//	 * 
//	 * @param secureMessage the message data to sign and encrypt.
//	 * @param signerCertificate the certificate used when signing.
//	 * @param signerInfoType indicates the type of SignerInfo inserted into generated messages, supported values are:
//	 * certificate_digest_with_ecdsap256 or certificate.
//	 * @param signAlg the signing public key algorithm scheme to use.
//	 * @param signPrivateKey the private key used to sign the message.
//	 * @param encryptionAlg encryption algorithm to use.
//	 * @param receipients a list of certificates of recipients, must have a encryption key specified in each certificate.
//	 * @return the message ITS Signature data structure containing the generated signature attached.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws GeneralSecurityException if internal problems occurred encrypting or generating the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	SecuredMessage encryptAndSignSecureMessage(SecuredMessage secureMessage, Certificate signerCertificate, 
//			    SignerInfoType signerInfoType, PublicKeyAlgorithm signAlg,
//				PrivateKey signPrivateKey, PublicKeyAlgorithm encryptionAlg, List<Certificate> receipients) throws IllegalArgumentException, GeneralSecurityException, IOException;
//	
//
//
	
	/**
	 * Method used to verify a IEEE Signature data structure given the digest and the signers public key
	 * 
	 * @param digest the digest to verify.
	 * @param signature the signature to verify.
	 * @param publicKey the signing public key.
	 * @return true if signature verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySignatureDigest(byte[] digest, Signature signature, PublicKey publicKey) throws IllegalArgumentException,  SignatureException, IOException;
	

	/**
	 * Method used to verify a ITS Signature data structure given the message and the signers public key
	 * 
	 * @param message the message to verify.
	 * @param signature the signature to verify.
	 * @param certType indicates if it is implicit or explicit signature
	 * @param signCert signing certificate, null if self signed
	 * @return true if signature verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySignature(byte[] message, Signature signature, CertificateType certType, Certificate signCert) throws IllegalArgumentException,  SignatureException, IOException;


//	/**
//	 * Method to verify a certificate that has the signers public key inside the certificate, 
//	 * i.e if SignerInfoType is self, certificate or certificate_chain
//	 * <p>
//	 * For other types use verifyCertificate(Certificate, Certificate)
//	 * <p>
//	 * <b>Important: this method only verifies the signature of the signer info public key (and for certificate_chain only the certificate above, not the entire chain). It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * @param certificate the certificate to verify.
//	 * 
//	 * @return true if certificate verifies.
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	boolean verifyCertificate(Certificate certificate) throws IllegalArgumentException,  SignatureException, IOException;
//
//	/**
//	 * Method used to verify a ITS Certificate data structure given the message with a given signers public key.
//	 * 
//	 * <b>Important: this method only verifies the signature of the signer info public key. It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * 
//	 * @param certificate the certificate to verify.
//	 * @param publicKey the signing public key.
//	 * @return true if certificate verifies.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	boolean verifyCertificate(Certificate certificate, EccPoint publicKey) throws IllegalArgumentException,  SignatureException, IOException;
//	
//	/**
//	 * Method used to verify a ITS Certificate data structure given the message with a given signers public key.
//	 * 
//	 * <b>Important: this method only verifies the signature of the signer info public key. It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * 
//	 * @param certificate the certificate to verify.
//	 * @param publicKey the signing public key.
//	 * @return true if certificate verifies.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	boolean verifyCertificate(Certificate certificate, PublicKey publicKey) throws IllegalArgumentException,  SignatureException, IOException;
//	
//	/**
//	 * Method used to verify a ITS Signature data structure given the message and the signers certificate.
//	 * 
//	 * <b>Important: this method only verifies the signature of the signer info public key. It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * 
//	 * @param certificate the certificate to verify.
//	 * @param signerCert the certificate signing the message.
//	 * @return true if certificate verifies.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	boolean verifyCertificate(Certificate certificate, Certificate signerCert) throws IllegalArgumentException,  SignatureException, IOException;
//	
//	/**
//	 * Method used to verify a ITS secure message that contains a signer info of type certificate, for certificate_digest_with_ecdsap256
//	 * it needed to use the alternative verifySecureMessage function and supplying the related certificate.
//	 * 
//	 * <b>Important: this method only verifies the signature of the signer info public key. It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * 
//	 * @param message the signed message to verify
//	 * @return true if secured message verifies
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws InvalidITSSignatureException if signature of message coundn't be verified.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	void verifySecuredMessage(SecuredMessage message) throws IllegalArgumentException,  InvalidITSSignatureException, SignatureException, IOException;
//	
//	
//	/**
//	 * Method used to verify a ITS secure message against a given certificate.
//	 * 
//	 * <b>Important: this method only verifies the signature of the signer info public key. It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * 
//	 * @param message the signed message to verify.
//	 * @param signerCert the certificate signing the message.
//	 * @return true if secured message verifies.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws InvalidITSSignatureException if signature of message coundn't be verified.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	void verifySecuredMessage(SecuredMessage message, Certificate signerCert) throws IllegalArgumentException,  InvalidITSSignatureException, SignatureException, IOException;
//	
//	
//	/**
//	 * Method used to verify and decrypt a ITS secure message that contains a signer info of type certificate, for certificate_digest_with_ecdsap256
//	 * it needed to use the alternative verifySecureMessage function and supplying the related certificate. The method also decrypts all
//	 * payloads of type signed_and_encrypted.
//	 * 
//	 * <b>Important: this method only verifies the signature of the signer info public key. It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * 
//	 * @param message the signed message to verify and decrypt
//	 * @param signerCert the certificate signing the message.
//	 * @param receiverCertificate the certificate for the private key used for decryption.
//	 * @param receiverKey the private key used to decrypt the message.
//	 * @return the secure message with all signed_and_encrypted payloads decrypted.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws InvalidITSSignatureException if signature of message coundn't be verified.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	SecuredMessage verifyAndDecryptSecuredMessage(SecuredMessage message,Certificate receiverCertificate, PrivateKey receiverKey) throws IllegalArgumentException, InvalidITSSignatureException, GeneralSecurityException, IOException;
//	
//	
//	/**
//	 * Method used to verify a ITS secure message against a given certificate. The method also decrypts all
//	 * payloads of type signed_and_encrypted.
//	 * 
//	 * <b>Important: this method only verifies the signature of the signer info public key. It
//	 * doesn't check any of the validation requirements or against trust store.</b>
//	 * 
//	 * @param message the signed message to verify and decrypt.
//	 * @param signerCert the certificate signing the message.
//	 * @param receiverCertificate the certificate for the private key used for decryption.
//	 * @param receiverKey the private key used to decrypt the message.
//	 * @return the secure message with all signed_and_encrypted payloads decrypted.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was invalid.
//	 * @throws InvalidITSSignatureException if signature of message coundn't be verified.
//	 * @throws SignatureException if internal problems occurred verifying the signature.
//	 * @throws IOException if communication problems occurred with underlying components.
//	 */
//	SecuredMessage verifyAndDecryptSecuredMessage(SecuredMessage message, Certificate signerCert ,Certificate receiverCertificate, PrivateKey receiverKey) throws IllegalArgumentException, InvalidITSSignatureException, GeneralSecurityException, IOException;
//
//	

	/**
	 * Help method used to convert a public key to a Ieee EccP256CurvePoint data structure.
	 * 
	 * @param alg the public key algorithm scheme to use.
	 * @param type the type of ECCPoint to create.
	 * @param publicKey the related public key to convert.
	 * @return a converted EccPoint data structure encoded according the the given ECC point type.
	 * @throws IllegalArgumentException if public key was invalid or unsupported
	 * @throws InvalidKeySpecException if the given public key contained invalid parameters related to the specified public key algorithm.
	 */
	EccP256CurvePoint encodeEccPoint(AlgorithmIndicator alg, EccP256CurvePointChoices type, PublicKey publicKey) throws IllegalArgumentException, InvalidKeySpecException;
	
	/**
	 * Help method to decode a EccP256CurvePoint to a EccPublic key or ECFieldElement depending on the type of EccPoint.
	 * 
	 * @param alg related public key algorithm.
	 * 
	 * @param eccPoint the ecc point to decode
	 * @return If EccPointType is not x_coordinate_only will only a BigInteger representing the ecdsa signature 'r' value, otherwise a PublicKey
	 * 
	 * @throws InvalidKeySpecException if problems occurred decoding the key.
	 */
	Object decodeEccPoint(AlgorithmIndicator alg, EccP256CurvePoint eccPoint) throws InvalidKeySpecException;
	
	
	

}