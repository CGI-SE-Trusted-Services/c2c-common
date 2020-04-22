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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.common.crypto.ECQVHelper;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;

/**
 * This structure is used for both implicit and explicit certificates.
 * 
 * The fields in this structure have the following meaning:
 * <p>
 *
 * <li>version contains the version of the certificate format. In this version of the data structures, this field is set to 3.</li>
 * <li>type states whether the certificate is implicit or explicit. This field is set to explicit for explicit certificates and to implicit for 
 * implicit certificates. See ExplicitCertificate and ImplicitCertificate for more details.</li>
 * <li>issuer identifies the issuer of the certificate.</li>
 * <li>toBeSigned is the certificate contents. This field is an input to the hash when generating or verifying signatures for an explicit certificate, 
 * or generating or verifying the public key from the reconstruction value for an implicit certificate. The details of how this field are encoded are 
 * given in the description of the ToBeSignedCertificate type.</li>
 * <li>signature is included in an ExplicitCertificate. It is the signature, calculated by the signer identified in the issuer field, over the hash 
 * of toBeSigned. The hash is calculated as specified in 5.3.1.</li>
 * </ul>
 * <br>
 * -Data input is the encoding of toBeSigned following the COER.
 * <br>
 * -Signer identifier input depends on the verification type, which in turn depends on the choice indicated by issuer. If the choice indicated by issuer 
 * is self, the verification type is self-signed and the signer identifier input is the empty string. If the choice indicated by issuer is not self, the 
 * verification type is certificate and the signer identifier input is the canonicalized COER encoding of the certificate indicated by issuer. The 
 * canonicalization is carried out as specified in the ENCODING CONSIDERATIONS section of this subclause.
 * <p>
 * <b>ENCODING CONSIDERATIONS:</b>When a certificate is encoded for hashing, for example to generate its
 * HashedId8, or when it is to be used as the signer identifier information for verification, it is canonicalized as follows:
 * <ul>
 * <li>The encoding of toBeSigned uses the compressed form for all elliptic curve points: that is, those points
 * indicate a choice of compressed- y-0 or compressed-y-1.</li>
 * <li>The encoding of the signature, if present and if an ECDSA signature, takes the r value to be an EccP256CurvePoint or EccP384CurvePoint indicating the choice x-only.</li>
 * </ul>
 * <p>
 *     <b>Whole-certificate hash:</b>If the entirety of a certificate is hashed to calculate a HashedId3, HashedId8, or
 * HashedId10, the algorithm used for this purpose is known as the whole-certificate hash.
 * <ul>
 * <li>The whole-certificate hash is SHA-256 if the certificate is an implicit certificate.</li>
 * <li>The whole-certificate hash is SHA-256 if the certificate is an explicit certificate and
 * toBeSigned.verifyKeyIndicator.verificationKey is an EccP256CurvePoint.</li>
 * <li>The whole-certificate hash is SHA-384 if the certificate is an explicit certificate and
 * toBeSigned.verifyKeyIndicator.verificationKey is an EccP384CurvePoint.</li>
 * </ul>
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Certificate extends COERSequence implements org.certificateservices.custom.c2x.common.Certificate {
	

	public static int CURRENT_VERSION = 3;
	
	private static final long serialVersionUID = 1L;
	
	protected static final int VERSION = 0;
	protected static final int TYPE = 1;
	protected static final int ISSUER = 2;
	protected static final int TOBESIGNED = 3;
	protected static final int SIGNATURE = 4;

	
	/**
	 * Constructor used when encoding explicit certificate
	 */
	public Certificate(int version, IssuerIdentifier issuer,
			ToBeSignedCertificate toBeSigned, Signature signature) throws IOException{
		super(false,5);
		init();
		
		if(signature == null){
			throw new IOException("Error Signature field must exist in explicit certificate");
		}
		if(toBeSigned != null && toBeSigned.getVerifyKeyIndicator().getType() != VerificationKeyIndicatorChoices.verificationKey){
			throw new IOException("Error explicit certificates has to have a verification key.");
		}
		
		set(VERSION, new Uint8(version));
		set(TYPE,new COEREnumeration(CertificateType.explicit));
		set(ISSUER, issuer);
		set(TOBESIGNED, toBeSigned);
		set(SIGNATURE, signature);		
	}

	/**
	 * Constructor used when encoding explicit certificate of default version
	 */
	public Certificate(IssuerIdentifier issuer,
			ToBeSignedCertificate toBeSigned,Signature signature) throws IOException{
		this(CURRENT_VERSION, issuer, toBeSigned,signature);	
	}
	
	/**
	 * Constructor used when encoding implicit certificate
	 */
	public Certificate(int version, IssuerIdentifier issuer,
			ToBeSignedCertificate toBeSigned) throws IOException{
		super(false,5);
		init();
		
		if(toBeSigned != null && toBeSigned.getVerifyKeyIndicator().getType() != VerificationKeyIndicatorChoices.reconstructionValue){
			throw new IOException("Error implicit certificates has to have a reconstruction value.");
		}
		
		set(VERSION, new Uint8(version));
		set(TYPE,new COEREnumeration(CertificateType.implicit));
		set(ISSUER, issuer);
		set(TOBESIGNED, toBeSigned);
		set(SIGNATURE, null);		
	}

	/**
	 * Constructor used when encoding implicit certificate of default version
	 */
	public Certificate(IssuerIdentifier issuer,
			ToBeSignedCertificate toBeSigned) throws IOException{
		this(CURRENT_VERSION, issuer, toBeSigned);	
	}
	
	/**
	 * Constructor used when decoding
	 */
	public Certificate(){
		super(false,5);
		init();
	}
	
	/**
	 * Constructor decoding a certificate from an encoded byte array.
	 * @param encodedCert byte array encoding of the certificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public Certificate(byte[] encodedCert) throws IOException{
		super(false,5);
		init();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedCert));
		decode(dis);
	}
	


	
	private void init(){
		addField(VERSION, false, new Uint8(), null);
		addField(TYPE, false, new COEREnumeration(CertificateType.class), null);
		addField(ISSUER, false, new IssuerIdentifier(), null);
		addField(TOBESIGNED, false, new ToBeSignedCertificate(), null);
		addField(SIGNATURE, true, new Signature(), null);
		
	}
	
	/**
	 * @return the version
	 */
	public int getVersion() {
		return (int) ((Uint8) get(VERSION)).getValueAsLong();
	}

	/**
	 * @return the certificate type
	 */
	public CertificateType getType() {
		return (CertificateType) ((COEREnumeration) get(TYPE)).getValue();
	}

	/**
	 * @return the issuer
	 */
	public IssuerIdentifier getIssuer() {
		return (IssuerIdentifier) get(ISSUER);
	}

	/**
	 * @return the toBeSigned value
	 */
	public ToBeSignedCertificate getToBeSigned() {
		return (ToBeSignedCertificate) get(TOBESIGNED);
	}

	/**
	 * @return the signature, optional
	 */
	public Signature getSignature() {
		return (Signature) get(SIGNATURE);
	}
	
	/**
	 * Encodes the certificate as a byte array.
	 * 
	 * @return return encoded version of the certificate as a byte[] 
	 * @throws IOException if encoding problems of the certificate occurred.
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		encode(dos);
		return baos.toByteArray();		
	}


	@Override
	public String toString() {
		return 
		"Certificate [\n" +
	    "  version=" + getVersion() + "\n" +
	    "  type=" + getType()+ "\n" +
	    "  issuer=" + getIssuer().toString().replaceAll("IssuerIdentifier ", "") + "\n" +
	    "  toBeSigned=" + getToBeSigned().toString().replaceAll("ToBeSignedCertificate ", "").replaceAll("\n","\n  ") + "\n" +
	    "  signature=" + ( getSignature() != null ? getSignature().toString().replaceAll("Signature ", "") : "NONE") + "\n" +
	    "]";
	}

	@Override
	public PublicKey getPublicKey(CryptoManager cryptoManager, AlgorithmIndicator alg, org.certificateservices.custom.c2x.common.Certificate signerCertificate, PublicKey signerCertificatePublicKey) throws InvalidKeySpecException, SignatureException, BadArgumentException {
		if(!(cryptoManager instanceof Ieee1609Dot2CryptoManager)){
			throw new BadArgumentException("Error extracting public key from IEEE 1609.2 certificate, related crypto manager must be a Ieee1609Dot2CryptoManager implementation.");
		}
		Ieee1609Dot2CryptoManager ieeeCryptoMgr = (Ieee1609Dot2CryptoManager) cryptoManager;
		if(getType() == CertificateType.implicit){
			if(!(signerCertificate instanceof Certificate)){
				throw new BadArgumentException("Error signerCertificate must be aIEEE 1609.2 certificate.");
			}
			if(!(signerCertificatePublicKey instanceof ECPublicKey)){
				throw new BadArgumentException("Error signerPublicKey must be of type be of type ECPublicKey.");
			}
			ECQVHelper helper = new ECQVHelper(ieeeCryptoMgr);
			
			BCECPublicKey bcCaPubKey = ieeeCryptoMgr.toBCECPublicKey(alg, (ECPublicKey) signerCertificatePublicKey);
			try {
				return helper.extractPublicKey(this, bcCaPubKey, alg, (Certificate) signerCertificate);
			} catch (IOException e) {
				throw new SignatureException("Error reconstructing implicit certificate public key: " + e.getMessage(),e);
			}
		}else{
			PublicVerificationKey pubVerKey = (PublicVerificationKey) getToBeSigned().getVerifyKeyIndicator().getValue();
			return (PublicKey) ieeeCryptoMgr.decodeEccPoint(pubVerKey.getType(),(EccP256CurvePoint) pubVerKey.getValue());
		}
	}

	@Override
	public Type getCertificateType() {
		if(getType() == CertificateType.implicit){
			return org.certificateservices.custom.c2x.common.Certificate.Type.IMPLICIT;
		}
		return org.certificateservices.custom.c2x.common.Certificate.Type.EXPLICIT;
	}

	/**
	 * Method to generate a HashedId8 Id for the Certificate using SHA-256 digest.
	 * @param cryptoManager the related crypto manager, must be compatible with underlying implementation.
	 * @return a newly generated HashedId8
	 * @throws IOException if problem occurred encoding this certificate to byte array.
	 * @throws NoSuchAlgorithmException if SHA-256 algorithm wasn't found in given CryptoManager.
	 */
	@Override
	public HashedId8 asHashedId8(CryptoManager cryptoManager) throws IOException, NoSuchAlgorithmException {
		try {
			return new HashedId8(cryptoManager.digest(getEncoded(),HashAlgorithm.sha256));
		} catch (BadArgumentException e) {
			throw new NoSuchAlgorithmException(e.getMessage(),e);
		}
	}
	
}
