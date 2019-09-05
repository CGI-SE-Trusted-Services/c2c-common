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
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccCurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint;
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
	 * @param privateKey the private key used to sign the message.
	 * @param certType the type of certificate (implicit or explicit)
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
	Signature signMessageDigest(byte[] digest, AlgorithmIndicator alg, PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException;
		
	
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
	 * Method to verify a self signed message without any generated certificate. Used when signing POP and
	 * related message.
	 * @param message the message to verify.
	 * @param signature the signature to verify.
	 * @param signedPublicKey the signing public key.
	 * @return true if signature verifies.
	 * @throws IllegalArgumentException if supplied arguments was invalid.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	boolean verifySelfSignedSignature(byte[] message, Signature signature, PublicKey signedPublicKey) throws IllegalArgumentException,  SignatureException, IOException;
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
	 * @param alg the algorithm used to encrypt the data.
	 * @param data the encrypted data.
	 * @param symmetricKey the encrypt key.
	 * @param nounce related nounce.
	 * @return the encrypt clear text data.
	 * 
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws GeneralSecurityException if internal problems occurred encrypting
	 */
	byte[] symmetricEncryptIEEE1609_2_2017(AlgorithmIndicator alg, byte[] data, byte[] symmetricKey, byte[] nounce) throws IllegalArgumentException, GeneralSecurityException;
	
	/**
	 * Help method to perform a symmetric decrypt of data.
	 * 
	 * @param alg the algorithm used to encrypt the data.
	 * @param data the encrypted data.
	 * @param symmetricKey the decryption key.
	 * @param nounce related nounce.
	 * @return the decrypted clear text data.
	 * 
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws GeneralSecurityException if internal problems occurred encrypting
	 */
	byte[] symmetricDecryptIEEE1609_2_2017(AlgorithmIndicator alg, byte[] data, byte[] symmetricKey, byte[] nounce) throws IllegalArgumentException,  GeneralSecurityException;


	/**
	 * Method to encrypt a symmetric key according to IEEE 1609.2 2017 specification.
	 *
	 * @param keyType the algorithm specification of the recipients public key.
	 * @param encryptionKey the recipients public key to encrypt to.
	 * @param symmetricKey the symmetric key to encrypt (Should be AES 128)
	 * @param p1 the deviation used as recipient information (SHA256 Hash of certificate or "" if no related certificate is available).
	 * @return a EncryptedDataEncryptionKey with v,c,t set.
	 * @throws IllegalArgumentException if supplied parameters where invalid.
	 * @throws GeneralSecurityException if problems occurred performing the encryption.
	 */
	EncryptedDataEncryptionKey ieeeEceisEncryptSymmetricKey2017(EncryptedDataEncryptionKeyChoices keyType, PublicKey encryptionKey, SecretKey symmetricKey, byte[] p1) throws IllegalArgumentException, GeneralSecurityException;

	/**
	 * Method to decrypt symmetric key using the 1609.2 2017 defined ECIES encryption scheme.
	 * @param encryptedDataEncryptionKey the type of encryption key.
	 * @param decryptionKey the receiver's private key.
	 * @param p1 the deviation used as recipient information (SHA256 Hash of certificate or "" if no related certificate is available).
	 * @return the decrypted AES symmetric key.
	 * @throws InvalidKeyException if supplied private key was invalid
	 * @throws IllegalArgumentException if invalid arguments where specified.
	 * @throws InvalidKeySpecException if invalid key specification was given.
	 */
	 SecretKey ieeeEceisDecryptSymmetricKey2017(EncryptedDataEncryptionKey encryptedDataEncryptionKey, PrivateKey decryptionKey, byte[] p1) throws InvalidKeyException, IllegalArgumentException, InvalidKeySpecException;
	 
	/**
	 * Method to convert a EC public key to a BCECPublicKey
	 * 
	 * @param alg specifying the related curve used.
	 * @param ecPublicKey key to convert
	 * @return a BCECPublicKey
	 * @throws InvalidKeySpecException if supplied key was invalid.
	 */
	BCECPublicKey toBCECPublicKey(AlgorithmIndicator alg, java.security.interfaces.ECPublicKey ecPublicKey) throws InvalidKeySpecException;
	
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
	 * Help method to decode a EccP256CurvePoint or EccP384CurvePoint to a EccPublic key or ECFieldElement depending on the type of EccPoint.
	 * 
	 * @param alg related public key algorithm.
	 * 
	 * @param eccPoint the ecc point to decode
	 * @return If EccPointType is not x_coordinate_only will only a BigInteger representing the ecdsa signature 'r' value, otherwise a PublicKey
	 * 
	 * @throws InvalidKeySpecException if problems occurred decoding the key.
	 */
	Object decodeEccPoint(AlgorithmIndicator alg, EccCurvePoint eccPoint) throws InvalidKeySpecException;

	/**
	 * Help method used to convert a public key to a Ieee EccP384CurvePoint data structure.
	 *
	 * @param alg the public key algorithm scheme to use.
	 * @param type the type of ECCPoint to create.
	 * @param publicKey the related public key to convert.
	 * @return a converted EccPoint data structure encoded according the the given ECC point type.
	 * @throws IllegalArgumentException if public key was invalid or unsupported
	 * @throws InvalidKeySpecException if the given public key contained invalid parameters related to the specified public key algorithm.
	 */
	EccP384CurvePoint encodeEccPoint(AlgorithmIndicator alg, EccP384CurvePoint.EccP384CurvePointChoices type, PublicKey publicKey) throws IllegalArgumentException, InvalidKeySpecException;


	/**
	 * Help method to generate a certificate digest according to 1609.2 section 5.3.1 Signature algorithm.
	 * @param alg the algorithm to use.
	 * @param messageData the message data to digest
	 * @param signerCertificate the certificate used for signing, null if selfsigned data.
	 * @throws NoSuchAlgorithmException 
	 * @throws IllegalArgumentException 
	 * @throws IOException 
	 */
	byte[] genIEEECertificateDigest(AlgorithmIndicator alg,byte[] messageData, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate) throws IllegalArgumentException, NoSuchAlgorithmException, IOException;

	/**
	 * Returns the related EC domain parameters for given algorithm.
	 * 
	 * @param alg algorithm to fetch domain parameters for.
	 * @return related EC domain parameters for given algorithm.
	 */
	ECParameterSpec getECParameterSpec(AlgorithmIndicator alg) throws IllegalArgumentException;
	
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
	PrivateKey reconstructImplicitPrivateKey(Certificate cert, BigInteger r, AlgorithmIndicator alg, PrivateKey Ku, PublicKey signerPublicKey, Certificate signerCertificate) throws IOException, IllegalArgumentException, SignatureException;
	

}