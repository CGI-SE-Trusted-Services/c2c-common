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
package org.certificateservices.custom.c2x.its.crypto;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage;

/**
 * Interface defining methods used by c2x specific cryptographic methods. 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public interface CryptoManager {
	
	/**
	 * Method that needs to be called before any calls to the crypto manager is performed, it
	 * should initialize all underlying components with the supplied paramteters. 
	 *  
	 * @throws IllegalArgumentException if supplied parameters contained invalid data.
	 * @throws NoSuchAlgorithmException if required underlying cryptographic algorithms doesn't exist in JVM.
	 * @throws NoSuchProviderException if required cryptographic providers couldn't be found in JVM.
	 * @throws IOException if communication problems occurred with underlying components.
	 * @throws BadCredentialsException if supplied credentials wasn't successful when authentication towards underlying hardware.
	 */
	void setupAndConnect(CryptoManagerParams params) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, IOException, BadCredentialsException;
	
	/**
	 * Method to sign a secured message using the given algorithm and private key and returns the same message with
	 * an attached signature according to the ITS specification with EccPointType x_coordinate_only containing the R value.
	 * 
	 * @param secureMessage the message data to sign.
	 * @param alg the public key algorithm scheme to use.
	 * @param privateKey the private key used to sign the message.
	 * @return the message ITS Signature data structure containing the generated signature attached.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	SecuredMessage signSecureMessage(SecuredMessage secureMessage, PublicKeyAlgorithm alg,
				PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException;
	/**
	 * Method used to sign the a message data according to the ITS specification with EccPointType x_coordinate_only containing the R value.
	 * 
	 * @param message the message data to sign.
	 * @param alg the public key algorithm scheme to use.
	 * @param privateKey the private key used to sign the message.
	 * @return a ITS Signature data structure containing the generated signature.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	Signature signMessage(byte[] message, PublicKeyAlgorithm alg, PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException;
	
	/**
	 * Method used to verify a ITS Signature data structure given the message and the signers public key
	 * 
	 * @param message the message to verify.
	 * @param signature the signature to verify.
	 * @param publicKey the signing public key.
	 * @return true if signature verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySignature(byte[] message, Signature signature, EccPoint publicKey) throws IllegalArgumentException,  SignatureException, IOException;

	/**
	 * Method used to verify a ITS Signature data structure given the message and the signers public key
	 * 
	 * @param message the message to verify.
	 * @param signature the signature to verify.
	 * @param publicKey the signing public key.
	 * @return true if signature verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySignature(byte[] message, Signature signature, PublicKey publicKey) throws IllegalArgumentException,  SignatureException, IOException;

	/**
	 * Method used to verify a ITS Signature data structure given the message and the signers certificate.
	 * 
	 * @param message the message to verify.
	 * @param signature the signature to verify.
	 * @param signerCert the certificate signing the message.
	 * @return true if signature verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySignature(byte[] message, Signature signature, Certificate signerCert) throws IllegalArgumentException,  SignatureException, IOException;

	/**
	 * Method to verify a certificate that has the signers public key inside the certificate, 
	 * i.e if SignerInfoType is self, certificate or certificate_chain
	 * <p>
	 * For other types use verifyCertificate(Certificate, Certificate)
	 * <p>
	 * <b>Important: this method only verifies the signature of the signer info public key (and for certificate_chain only the certificate above, not the entire chain). It
	 * doesn't check any of the validation requirements or against trust store.</b>
	 * @param certificate the certificate to verify.
	 * 
	 * @return true if certificate verifies.
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifyCertificate(Certificate certificate) throws IllegalArgumentException,  SignatureException, IOException;

	/**
	 * Method used to verify a ITS Certificate data structure given the message with a given signers public key.
	 * 
	 * <b>Important: this method only verifies the signature of the signer info public key. It
	 * doesn't check any of the validation requirements or against trust store.</b>
	 * 
	 * @param certificate the certificate to verify.
	 * @param publicKey the signing public key.
	 * @return true if certificate verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifyCertificate(Certificate certificate, EccPoint publicKey) throws IllegalArgumentException,  SignatureException, IOException;
	
	/**
	 * Method used to verify a ITS Certificate data structure given the message with a given signers public key.
	 * 
	 * <b>Important: this method only verifies the signature of the signer info public key. It
	 * doesn't check any of the validation requirements or against trust store.</b>
	 * 
	 * @param certificate the certificate to verify.
	 * @param publicKey the signing public key.
	 * @return true if certificate verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifyCertificate(Certificate certificate, PublicKey publicKey) throws IllegalArgumentException,  SignatureException, IOException;
	
	/**
	 * Method used to verify a ITS Signature data structure given the message and the signers certificate.
	 * 
	 * <b>Important: this method only verifies the signature of the signer info public key. It
	 * doesn't check any of the validation requirements or against trust store.</b>
	 * 
	 * @param certificate the certificate to verify.
	 * @param signerCert the certificate signing the message.
	 * @return true if certificate verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifyCertificate(Certificate certificate, Certificate signerCert) throws IllegalArgumentException,  SignatureException, IOException;
	
	/**
	 * Method used to verify a ITS secure message that contains a signer info of type certificate, for certificate_digest_with_ecdsap256
	 * it needed to use the alternative verifySecureMessage function and supplying the related certificate.
	 * 
	 * <b>Important: this method only verifies the signature of the signer info public key. It
	 * doesn't check any of the validation requirements or against trust store.</b>
	 * 
	 * @param message the signed message to verify
	 * @return true if secured message verifies
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySecuredMessage(SecuredMessage message) throws IllegalArgumentException,  SignatureException, IOException;
	
	
	/**
	 * Method used to verify a ITS secure message against a given certificate.
	 * 
	 * <b>Important: this method only verifies the signature of the signer info public key. It
	 * doesn't check any of the validation requirements or against trust store.</b>
	 * 
	 * @param message the signed message to verify.
	 * @param signerCert the certificate signing the message.
	 * @return true if secured message verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySecuredMessage(SecuredMessage message, Certificate signerCert) throws IllegalArgumentException,  SignatureException, IOException;
	
	
	
	/**
	 * Method to generate a new key pair for the given public key algorithm scheme.
	 * 
	 * @param alg publicKey the signing public key.
	 * 
	 * @return a new key pair.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws IOException if communication problems occurred with underlying components.
	 * @throws InvalidKeyException if other non-IO related problems occurred generating the key. 
	 */
	KeyPair generateKeyPair(PublicKeyAlgorithm alg) throws IllegalArgumentException, IOException,InvalidKeyException;
	
	/**
	 * Help method used to convert a public key to a EccPoint data structure.
	 * 
	 * @param alg the public key algorithm scheme to use.
	 * @param type the type of ECCPoint to create.
	 * @param publicKey the related public key to convert.
	 * @return a converted EccPoint data structure encoded according the the given ECC point type.
	 * @throws IllegalArgumentException if public key was invalid or unsupported
	 * @throws InvalidKeySpecException if the given public key contained invalid parameters related to the specified public key algorithm.
	 */
	EccPoint encodeEccPoint(PublicKeyAlgorithm alg, EccPointType type, PublicKey publicKey) throws IllegalArgumentException, InvalidKeySpecException;
	
	/**
	 * Help method to decode a EccPoint to a EccPublic key or ECFieldElement depending on the type of EccPoint.
	 * 
	 * @param alg related public key algorithm.
	 * 
	 * @param eccPoint the ecc point to decode
	 * @return If EccPointType is not x_coordinate_only will only a BigInteger representing the ecdsa signature 'r' value, otherwise a PublicKey
	 * 
	 * @throws InvalidKeySpecException if problems occurred decoding the key.
	 */
	Object decodeEccPoint(PublicKeyAlgorithm alg, EccPoint eccPoint) throws InvalidKeySpecException;
	
	
	
	/**
	 * Method to generate a digest of a message using the given public key algorithm scheme.
	 * 
	 * @param message the message data to generate a digest from.
	 * @param alg the related public key algorithm scheme to use.
	 * @return a digest of the message.
	 * 
	 * @throws IllegalArgumentException if an unsupported public key algorithm scheme was given.
	 * @throws NoSuchAlgorithmException if related cryptographic algorithm wasn't available in JVM.
	 */
	byte[] digest(byte[] message, PublicKeyAlgorithm alg) throws IllegalArgumentException, NoSuchAlgorithmException;
	
	/**
	 * Method signaling to underlying components to release resources.
	 * 
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	void disconnect() throws IOException;
}