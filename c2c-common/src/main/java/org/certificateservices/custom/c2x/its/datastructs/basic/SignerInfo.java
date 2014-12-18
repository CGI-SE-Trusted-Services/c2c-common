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
package org.certificateservices.custom.c2x.its.datastructs.basic;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.List;

import org.certificateservices.custom.c2x.its.datastructs.SerializationHelper;
import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;


/**
 * This structure defines how to give information about the signer of a message. The included cryptographic identity can
 * be used in conjunction with the structure Signature to verify a message's authenticity. Depending on the value of
 * type, the SignerInfo's data fields shall contain the following entries:
 * <li> self: the data is self-signed. Therefore, no additional data shall be given. This shall only be used in case of a certificate request.
 * <li> certificate_digest_with_ecdsap256: an 8 octet digest of the relevant certificate contained in a HashedId8 structure shall be given.
 * <li> certificate: the relevant certificate itself contained in a Certificate structure shall be given.
 * <li> certificate_chain: a complete certificate chain contained in a variable-length vector of type Certificate shall be given. 
 * The last element of the chain shall contain the certificate used to sign the message, the next to last element shall contain 
 * the certificate of the CA that signed the last certificate and so on. The first element of the chain needs not be a root certificate.
 * <li>certificate_digest_with_other_algorithm: an 8 octet digest contained in a HashedId8 structure and the corresponding 
 * public key algorithm contained in a PublicKeyAlgorithm structure shall be given.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SignerInfo implements StructSerializer{
	

	private SignerInfoType signerInfoType;
	private HashedId8 digest;
	private Certificate certificate;
	private List<Certificate> certificateChain;
	private PublicKeyAlgorithm publicKeyAlgorithm;
	

	/**
	 * Constructor used during serializing or signer info type: self
	 * 
	 */
	public SignerInfo(){
		signerInfoType = SignerInfoType.self;
	}
	
	/**
	 * Constructor for a signer info of type: certificate_digest_with_ecdsap256.
	 * @param digest an 8 octet digest of the relevant certificate contained in a HashedId8 structure shall be given.
	 */
	public SignerInfo(HashedId8 digest) {
		this.signerInfoType = SignerInfoType.certificate_digest_with_ecdsap256;
		this.digest = digest;
	}
	
	/**
	 * Constructor for a signer info of type: certificate.
	 * @param certificate the relevant certificate itself contained in a Certificate structure shall be given.
	 */
	public SignerInfo(Certificate certificate) {
		this.signerInfoType = SignerInfoType.certificate;
		this.certificate = certificate;
	}
	
	/**
	 * Constructor for a signer info of type: certificate_chain.
	 * @param certificateChain a complete certificate chain contained in a variable-length vector of type 
	 * Certificate shall be given. The last element of the chain shall contain the certificate used to sign the
	 * message, the next to last element shall contain the certificate of the CA that signed the last certificate and so
	 * on. The first element of the chain needs not be a root certificate.
	 */
	public SignerInfo(List<Certificate> certificateChain) {
		this.signerInfoType = SignerInfoType.certificate_chain;
		this.certificateChain = certificateChain;
	}
	
	/**
	 * Constructor for a signer info of type: certificate_digest_with_other_algorithm.
	 * 
     * @param publicKeyAlgorithm the corresponding public key algorithm contained in a PublicKeyAlgorithm structure shall 
     * be given.
	 * @param digest an 8 octet digest contained in a HashedId8 structure,
	 */
	public SignerInfo(PublicKeyAlgorithm publicKeyAlgorithm, HashedId8 digest) {
		this.signerInfoType = SignerInfoType.certificate_digest_with_other_algorithm;
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.digest = digest;
	}
	




	/**
	 * @return the type of signer info, one of SignerInfoType enum values
	 */
	public SignerInfoType getSignerInfoType() {
		return signerInfoType;
	}

	/**
	 * @return an 8 octet digest of the relevant certificate contained in a HashedId8 structure.
	 * <p>
	 * This value is only applicable if signerInfoType is certificate_digest_with_ecdsap256 or certificate_digest_with_other_algorithm.
	 */
	public HashedId8 getDigest() {
		return digest;
	}

	/**
	 * @return the relevant certificate itself contained in a Certificate structure.
	 * <p>
	 * This value is only applicable if signerInfoType is certificate
	 */
	public Certificate getCertificate() {
		return certificate;
	}

	/**
	 * @return a complete certificate chain contained in a variable-length vector of type 
	 * Certificate shall be given. The last element of the chain shall contain the certificate used to sign the
	 * message, the next to last element shall contain the certificate of the CA that signed the last certificate and so
	 * on. The first element of the chain needs not be a root certificate.
	 * <p>
	 * This value is only applicable if signerInfoType is certificate_chain.
	 */
	public List<Certificate> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * @return the publicKeyAlgorithm the corresponding public key algorithm contained in a PublicKeyAlgorithm structure. 
	 * <p>
	 * This value is only applicable if signerInfoType is certificate_digest_with_other_algorithm.
	 */
	public PublicKeyAlgorithm getPublicKeyAlgorithm() {
		return publicKeyAlgorithm;
	}

	@Override
	public void serialize(DataOutputStream out) throws IOException {
		out.write(signerInfoType.getByteValue());
		switch (signerInfoType) {
		case self:
			break;
		case certificate_digest_with_ecdsap256:
			digest.serialize(out);
			break;
        case certificate:
			certificate.serialize(out);
			break;
        case certificate_chain:			
        	SerializationHelper.encodeVariableSizeVector(out, certificateChain);    		
			break;
        case certificate_digest_with_other_algorithm:
        	out.write(publicKeyAlgorithm.getByteValue());
        	digest.serialize(out);
			break;
		default:
			break;
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void deserialize(DataInputStream in) throws IOException {
		signerInfoType = SignerInfoType.getByValue(in.readByte());
		switch (signerInfoType) {
		case self:
			break;
		case certificate_digest_with_ecdsap256:
			digest = new HashedId8();
			digest.deserialize(in);
			break;
        case certificate:
        	certificate = new Certificate();
        	certificate.deserialize(in);
        	break;
        case certificate_chain:        
    		certificateChain = (List<Certificate>) SerializationHelper.decodeVariableSizeVector(in, Certificate.class);
			break;
        case certificate_digest_with_other_algorithm:
        	publicKeyAlgorithm = PublicKeyAlgorithm.getByValue(in.readByte());
			digest = new HashedId8();
			digest.deserialize(in);
			break;
		default:
			break;
		}
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((certificate == null) ? 0 : certificate.hashCode());
		result = prime
				* result
				+ ((certificateChain == null) ? 0 : certificateChain.hashCode());
		result = prime * result + ((digest == null) ? 0 : digest.hashCode());
		result = prime
				* result
				+ ((publicKeyAlgorithm == null) ? 0 : publicKeyAlgorithm
						.hashCode());
		result = prime * result
				+ ((signerInfoType == null) ? 0 : signerInfoType.hashCode());
		return result;
	}


	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignerInfo other = (SignerInfo) obj;
		if (certificate == null) {
			if (other.certificate != null)
				return false;
		} else if (!certificate.equals(other.certificate))
			return false;
		if (certificateChain == null) {
			if (other.certificateChain != null)
				return false;
		} else if (!certificateChain.equals(other.certificateChain))
			return false;
		if (digest == null) {
			if (other.digest != null)
				return false;
		} else if (!digest.equals(other.digest))
			return false;
		if (publicKeyAlgorithm != other.publicKeyAlgorithm)
			return false;
		if (signerInfoType != other.signerInfoType)
			return false;
		return true;
	}



	@Override
	public String toString() {
		switch (signerInfoType) {
		case self:
			return "SignerInfo [signerInfoType=" + signerInfoType + "]";
        case certificate_digest_with_ecdsap256:
    		return "SignerInfo [signerInfoType=" + signerInfoType + ", digest="
			+ digest +"]";
        case certificate:
    		return "SignerInfo [signerInfoType=" + signerInfoType + ", certificate=" + certificate + "]";
        case certificate_chain:
    		return "SignerInfo [signerInfoType=" + signerInfoType 
			+ ", certificateChain=" + certificateChain + "]";
        case certificate_digest_with_other_algorithm:
    		return "SignerInfo [signerInfoType=" + signerInfoType + ", digest="
			+ digest + ", publicKeyAlgorithm=" + publicKeyAlgorithm + "]";
		default:
			break;
		}
		return "SignerInfo [signerInfoType=" + signerInfoType + "]";
	}



}
