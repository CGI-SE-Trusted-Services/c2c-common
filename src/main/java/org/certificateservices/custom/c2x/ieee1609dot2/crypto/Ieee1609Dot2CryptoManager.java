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
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;


/**
 * Interface defining methods used by c2x specific cryptographic methods. 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public interface Ieee1609Dot2CryptoManager extends CryptoManager {
	


	/**
	 * Method used to sign the a message data according to the IEEE specification with EccPointType x_coordinate_only containing the R value.
	 * 
	 * @param message the message data to sign.
	 * @param alg the public key algorithm scheme to use.
	 * @param publicKey the public key of the certificate.
	 * @param privateKey the private key used to sign the message.
	 * @param certType the type of certificate (implicit or explicit)
	 * @param signingCert the signer or null if self signed.
	 * @return a IEEE 1609.2 Signature data structure containing the generated signature.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	Signature signMessage(byte[] message, AlgorithmIndicator alg, PublicKey publicKey, PrivateKey privateKey, CertificateType certType, Certificate signingCert) throws IllegalArgumentException, SignatureException, IOException;
	
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
	 * Method used to verify a IEEE Signature data structure given the message and the signers explicit certificate, 
	 * 
	 * @param message the message to verify.
	 * @param signature the signature to verify.
	 * @param signCert signing certificate, required, for self signed certificate use separate method.
	 * @return true if signature verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySignature(byte[] message, Signature signature, Certificate signCert) throws IllegalArgumentException,  SignatureException, IOException;

	/**
	 * Method used to verify a IEEE Signature data structure given the message and the signers implicit certificate, 
	 * 
	 * @param message the message to verify.
	 * @param signature the signature to verify.
	 * @param signCert signing certificate, required, for self signed certificate use separate method.
	 * @param signedPublicKey the signing public key.
	 * @return true if signature verifies.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySignature(byte[] message, Signature signature, Certificate signCert, PublicKey signedPublicKey) throws IllegalArgumentException,  SignatureException, IOException;

	
	/**
	 * Method to verify a certificate with a given signer certificate
	 * 
	 * @param certificate the certificate to verify.
	 * @param signerCertificate the signer certificate 
	 * 
	 * @return true if certificate verifies.
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifyCertificate(Certificate certificate, Certificate signerCertificate) throws IllegalArgumentException,  SignatureException, IOException;

	/**
	 * Method to generate a nounce for the given algorithm.
	 * 
	 * @param alg algorithm indicator that must support symmetric scheme.
	 * @return a freshly generated nounce
	 * @throws IllegalArgumentException if algorithm didn't support symmetric algorithm.
	 * @throws GeneralSecurityException if internal problems occurred generating the random nounce.  
	 */
	 byte[] genNounce(AlgorithmIndicator alg) throws IllegalArgumentException, GeneralSecurityException; 

	/**
	 * Method to reconstruct a symmetric from byte encoding.
	 * @param alg type of symmetric algorithm
	 * @param keyData the raw key data.
	 * @return a reconstructed symmetric key.
	 * @throws IllegalArgumentException if algorithm didn't support symmetric algorithm or key data was invalid.
	 * @throws GeneralSecurityException if internal problems occurred reconstructing the secret key.  
	 */
	 SecretKey constructSecretKey(AlgorithmIndicator alg, byte[] keyData) throws IllegalArgumentException, GeneralSecurityException;
	
	/**
	 * Help method to perform a symmetric encrypt of data.
	 * 
	 * @param symmetricAlgorithm the algorithm used to encrypt the data.
	 * @param data the encrypted data.
	 * @param symmetricKey the encrypt key.
	 * @param nounce related nounce.
	 * @return the encrypt clear text data.
	 * 
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws GeneralSecurityException if internal problems occurred encrypting
	 */
	 byte[] symmetricEncrypt(AlgorithmIndicator alg, byte[] data, Key symmetricKey, byte[] nounce) throws IllegalArgumentException, GeneralSecurityException;
	
	/**
	 * Help method to perform a symmetric decrypt of data.
	 * 
	 * @param symmetricAlgorithm the algorithm used to encrypt the data.
	 * @param data the encrypted data.
	 * @param symmetricKey the decryption key.
	 * @param nounce related nounce.
	 * @return the decrypted clear text data.
	 * 
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws GeneralSecurityException if internal problems occurred encrypting
	 */
	 byte[] symmetricDecrypt(AlgorithmIndicator alg, byte[] data, Key symmetricKey, byte[] nounce) throws IllegalArgumentException, GeneralSecurityException;
	
	
	/**
	 * Help method to perform a ECIES encryption to a recipient of a symmetric key. 
	 * 
	 * @param keyType type of encryption key used.
	 * @param encryptionKey the public encryption key of the recipient
	 * @param symmetricKey the symmetric key to encrypt
	 * @param alg related algorithm specifying symmetric algorithm to use.
	 * @param eciesDeviation deviation parameter used as P1 parameter in ECIES algorithm
	 * @return a EncryptedDataEncryptionKey used in RecepientInfo 
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws GeneralSecurityException if internal problems occurred encrypting the symmetric key.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	 EncryptedDataEncryptionKey eCEISEncryptSymmetricKey(EncryptedDataEncryptionKeyChoices keyType, PublicKey encryptionKey, SecretKey symmetricKey, AlgorithmIndicator alg,byte[] eciesDeviation) throws IllegalArgumentException, GeneralSecurityException, IOException;
	
	 /**
	  * Help method to perform a ECIES decryption by a recipient to retrieve the symmetric key. 
	 * 
	 * @param encryptedDataEncryptionKey the symmetric key envelope
	 * @param decryptionKey the decryption key to decrypt the envelope.
	 * @param alg related algorithm specifying symmetric algorithm to use.
	 * @param eciesDeviation deviation parameter used as P1 parameter in ECIES algorithm
	 * @return a symmetric decryption key of the actual message data.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws GeneralSecurityException if internal problems occurred decrypting the symmetric key.
	 * @throws IOException if communication problems occurred with underlying components.
	  */
	 SecretKey eCEISDecryptSymmetricKey(EncryptedDataEncryptionKey encryptedDataEncryptionKey, PrivateKey decryptionKey, AlgorithmIndicator alg, byte[] eciesDeviation) throws IllegalArgumentException, GeneralSecurityException, IOException;
	 
	/**
	 * Method to convert a EC public key to a BCECPublicKey
	 * 
	 * @param alg specifying the related curve used.
	 * @param ecPublicKey key to convert
	 * @return a BCECPublicKey
	 * @throws InvalidKeySpecException if supplied key was invalid.
	 */
	public BCECPublicKey toBCECPublicKey(AlgorithmIndicator alg, java.security.interfaces.ECPublicKey ecPublicKey) throws InvalidKeySpecException;
	
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
	
	/**
	 * Help method to generate a certificate digest according to 1609.2 section 5.3.1 Signature algorithm.
	 * @param alg the algorithm to use.
	 * @param messageData the message data to digest
	 * @param signerCertificate the certificate used for signing, null if selfsigned data.
	 * @throws NoSuchAlgorithmException 
	 * @throws IllegalArgumentException 
	 * @throws IOException 
	 */
	public byte[] genIEEECertificateDigest(AlgorithmIndicator alg,byte[] messageData, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate) throws IllegalArgumentException, NoSuchAlgorithmException, IOException;

	/**
	 * Returns the related EC domain parameters for given algorithm.
	 * 
	 * @param alg algorithm to fetch domain parameters for.
	 * @return related EC domain parameters for given algorithm.
	 */
	public ECParameterSpec getECParameterSpec(AlgorithmIndicator alg) throws IllegalArgumentException;
	
	/**
	 * Method to construct the private key related to a generate certificate, given the related r value.
	 * 
	 * @param cert the generated certificate.
	 * @param r the private key r value
	 * @param alg the related algorithm
	 * @param Ku the private key generate for the certificate request.
	 * @param signerPublicKey the CA public key.
	 * @param signerCertificate the CA certificate
	 * @return a generated private key.
	 * @throws IOException if communication problems occurred with underlying systems.
	 * @throws IllegalArgumentException if argument was illegal
	 * @throws SignatureException if internal problems occurred constructing the certificate private key.
	 */
	public PrivateKey reconstructImplicitPrivateKey(Certificate cert, BigInteger r, AlgorithmIndicator alg, PrivateKey Ku, PublicKey signerPublicKey, Certificate signerCertificate) throws IOException, IllegalArgumentException, SignatureException;
	

}