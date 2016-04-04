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
package org.certificateservices.custom.c2x.its.datastructs.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.EncodeHelper.ToStringCallback;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;

/**
 * This structure defines how to encode a certificate.
 * <li> version specifies this certificate's version and shall be set to 1 or 2 depending on version.
 * <li> Information on this certificate's signer is given in the variable-length vector signer_info.
 * <li> subject_info specifies information on this certificate's subject.  Further information on the subject is 
 * given in the variable-length vector subject_attributes. The elements in the subject_attributes array shall be 
 * encoded in ascending numerical order of their type value, unless this is specifically overridden by a security profile. 
 * subject_attributes shall not contain two entries with the same type value.
 * <li> The variable-length vector validity_restrictions specifies restrictions regarding this certificate's validity. 
 * The elements in the validity_restrictions array shall be encoded in ascending numerical order of their type value, 
 * unless this is specifically overridden by a security profile. validity_restrictions shall not contain two entries with the same type value.
 * <li> signature holds the signature of this certificate signed by the responsible CA. The signature shall be calculated over the 
 * encoding of all preceding fields, including all encoded lengths. If the subject_attributes field contains a field of type 
 * reconstruction_value, the signature field shall be omitted.
 * <p>
 * NOTE 1: A certificate is considered valid if the current time is within the validity period specified in the certificate, the current region 
 * is within the validity region specified in the certificate, the type of the certificate is valid for the current type of communication, 
 * the signature, which covers all fields except the signature itself, is valid, and the certificate of the signer is valid as signer for the 
 * given certificate's type. If the certificate is self-signed, it is valid if it is stored as a trusted certificate.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Certificate implements Encodable, org.certificateservices.custom.c2x.common.Certificate {
	
	public static final int CERTIFICATE_VERSION_1 = 1;
	public static final int CERTIFICATE_VERSION_2 = 2;
	
	public static final int DEFAULT_CERTIFICATE_VERSION = CERTIFICATE_VERSION_2;

	
	private int version;
	private List<SignerInfo> signerInfos;
	private SubjectInfo subjectInfo;
	private List<SubjectAttribute> subjectAttributes;
	private List<ValidityRestriction> validityRestrictions;
	private Signature signature;

	/**
	 * Main constructor for a certificate template without any signature attached.
	 *  
	 * @param version specifies this certificate's version.
	 * @param signerInfos information on this certificate's signer
	 * @param subjectInfo specifies information on this certificate's subject.
	 * @param subjectAttributes Further information on the subject is given in the variable-length vector subject_attributes. The
	 * elements in the subject_attributes array shall be encoded in ascending numerical order of their type
	 * value, unless this is specifically overridden by a security profile. subject_attributes shall not contain
	 * two entries with the same type value.
	 * @param validityRestrictions  specifies restrictions regarding this certificate's
	 * validity. The elements in the validity_restrictions array shall be encoded in ascending numerical
	 * order of their type value, unless this is specifically overridden by a security profile.
	 * validity_restrictions shall not contain two entries with the same type value.
	 */
	public Certificate(int version, 
			List<SignerInfo> signerInfos, 
			SubjectInfo subjectInfo, 
			List<SubjectAttribute> subjectAttributes,  
			List<ValidityRestriction> validityRestrictions){
		this.version = version;
		this.signerInfos = signerInfos;
		this.subjectInfo = subjectInfo;
		this.subjectAttributes = subjectAttributes;
		this.validityRestrictions = validityRestrictions;		
	}
	
	/**
	 * Main constructor for a certificate template without any signature attached for version 2 certificates
	 *  
	 * @param signerInfos information on this certificate's signer
	 * @param subjectInfo specifies information on this certificate's subject.
	 * @param subjectAttributes Further information on the subject is given in the variable-length vector subject_attributes. The
	 * elements in the subject_attributes array shall be encoded in ascending numerical order of their type
	 * value, unless this is specifically overridden by a security profile. subject_attributes shall not contain
	 * two entries with the same type value.
	 * @param validityRestrictions  specifies restrictions regarding this certificate's
	 * validity. The elements in the validity_restrictions array shall be encoded in ascending numerical
	 * order of their type value, unless this is specifically overridden by a security profile.
	 * validity_restrictions shall not contain two entries with the same type value.
	 * @throws IllegalArgumentException for invalid parameters.
	 */
	public Certificate(
			SignerInfo signerInfo, 
			SubjectInfo subjectInfo, 
			List<SubjectAttribute> subjectAttributes,  
			List<ValidityRestriction> validityRestrictions){
		this(CERTIFICATE_VERSION_2, null, subjectInfo, subjectAttributes, validityRestrictions);
		if(signerInfo == null){
			throw new IllegalArgumentException("Error a SignerInfo must be specified for version 2 certificates");
		}
		checkSignerInfoType(signerInfo.getSignerInfoType());
		signerInfos = new ArrayList<SignerInfo>();
		signerInfos.add(signerInfo);
	}
	


	/**
	 * Main constructor for a certificate template without any signature attached for version 1 certificates
	 *  
	 * @param signerInfos information on this certificate's signer
	 * @param subjectInfo specifies information on this certificate's subject.
	 * @param subjectAttributes Further information on the subject is given in the variable-length vector subject_attributes. The
	 * elements in the subject_attributes array shall be encoded in ascending numerical order of their type
	 * value, unless this is specifically overridden by a security profile. subject_attributes shall not contain
	 * two entries with the same type value.
	 * @param validityRestrictions  specifies restrictions regarding this certificate's
	 * validity. The elements in the validity_restrictions array shall be encoded in ascending numerical
	 * order of their type value, unless this is specifically overridden by a security profile.
	 * validity_restrictions shall not contain two entries with the same type value.
	 */
	public Certificate(
			List<SignerInfo> signerInfos, 
			SubjectInfo subjectInfo, 
			List<SubjectAttribute> subjectAttributes,  
			List<ValidityRestriction> validityRestrictions){
		this(CERTIFICATE_VERSION_1, signerInfos, subjectInfo, subjectAttributes, validityRestrictions);		
	}
	

	
	/**
	 * Main constructor for a certificate with an attached signature.
	 *  
	 * @param version specifies this certificate's version.
	 * @param signerInfos information on this certificate's signer, only one for version 2 certificates.
	 * @param subjectInfo specifies information on this certificate's subject.
	 * @param subjectAttributes further information on the subject is given in the variable-length vector subject_attributes. The
	 * elements in the subject_attributes array shall be encoded in ascending numerical order of their type
	 * value, unless this is specifically overridden by a security profile. subject_attributes shall not contain
	 * two entries with the same type value.
	 * @param validityRestrictions  specifies restrictions regarding this certificate's
	 * validity. The elements in the validity_restrictions array shall be encoded in ascending numerical
	 * order of their type value, unless this is specifically overridden by a security profile.
	 * validity_restrictions shall not contain two entries with the same type value.
	 * @param signature holds the signature of this certificate signed by the responsible CA. The signature shall be
	 * calculated over the encoding of all preceding fields, including all encoded lengths. If the subject_attributes
	 * field contains a field of type reconstruction_value, the signature field shall be omitted.
	 * @throws IllegalArgumentException for invalid parameters.
	 */
	public Certificate(int version, 
			List<SignerInfo> signerInfos, 
			SubjectInfo subjectInfo, 
			List<SubjectAttribute> subjectAttributes,  
			List<ValidityRestriction> validityRestrictions,
			Signature signature) throws IllegalArgumentException{
		this(version, signerInfos, subjectInfo, subjectAttributes, validityRestrictions);
		if(version != 1 ){
			if(signerInfos.size() != 1){
			  throw new IllegalArgumentException("Error Version 2 certificates can only contain one SignerInfo");
			}
			checkSignerInfoType(signerInfos.get(0).getSignerInfoType());
		}
		
		this.signature = signature;
	}
	

	/**
	 * Constructor creating a certificate from an encoded byte array.
	 * @param encodedCert byte array encoding of the certificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public Certificate(byte[] encodedCert) throws IOException{
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedCert));
		decode(dis);
	}
	
	/**
	 * Constructor used during serialization
	 */
	public Certificate(){}
	
    /**
     * Attaches a generated signature to the structure.
     * @param signature
     */
	public void attachSignature(Signature signature){
		this.signature = signature;
	}

	/**
	 * @return the version specifies this certificate's version.
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * @return the signerInfos information on this certificate's signer
	 */
	public List<SignerInfo> getSignerInfos() {
		return signerInfos;
	}

	/**
	 * @return the subjectInfo specifies information on this certificate's subject.
	 */
	public SubjectInfo getSubjectInfo() {
		return subjectInfo;
	}

	/**
	 * @return the subjectAttributes further information on the subject is given in the variable-length vector subject_attributes. The
	 * elements in the subject_attributes array shall be encoded in ascending numerical order of their type
	 * value, unless this is specifically overridden by a security profile. subject_attributes shall not contain
	 * two entries with the same type value.
	 */
	public List<SubjectAttribute> getSubjectAttributes() {
		return subjectAttributes;
	}

	/**
	 * @return the validityRestrictions  specifies restrictions regarding this certificate's
	 * validity. The elements in the validity_restrictions array shall be encoded in ascending numerical
	 * order of their type value, unless this is specifically overridden by a security profile.
	 * validity_restrictions shall not contain two entries with the same type value.
	 */
	public List<ValidityRestriction> getValidityRestrictions() {
		return validityRestrictions;
	}

	/**
	 * @return the signature holds the signature of this certificate signed by the responsible CA. The signature shall be
	 * calculated over the encoding of all preceding fields, including all encoded lengths. If the subject_attributes
	 * field contains a field of type reconstruction_value, the signature field shall be omitted.
	 * <p>
	 * Could be null if no signature is attached.
	 */
	public Signature getSignature() {
		return signature;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(version);		
		if(version == CERTIFICATE_VERSION_1){
		  EncodeHelper.encodeVariableSizeVector(out, signerInfos);
		}else{
			signerInfos.get(0).encode(out);
		}
		subjectInfo.encode(out);
		EncodeHelper.encodeVariableSizeVector(out, subjectAttributes);
		EncodeHelper.encodeVariableSizeVector(out, validityRestrictions);		
		if(signature != null){
			signature.encode(out);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void decode(DataInputStream in) throws IOException {
		version = in.read();
		if(version == CERTIFICATE_VERSION_1){
			signerInfos = (List<SignerInfo>) EncodeHelper.decodeVariableSizeVector(in, SignerInfo.class);
		}else{
			SignerInfo signerInfo = new SignerInfo();
			signerInfo.decode(in);
			signerInfos = new ArrayList<SignerInfo>();
			signerInfos.add(signerInfo);
		}
		
		subjectInfo = new SubjectInfo();
		subjectInfo.decode(in);
		
		subjectAttributes = (List<SubjectAttribute>) EncodeHelper.decodeVariableSizeVector(in, SubjectAttribute.class);
		
		validityRestrictions = (List<ValidityRestriction>) EncodeHelper.decodeVariableSizeVector(in, ValidityRestriction.class);
				
		signature = new Signature();
		signature.decode(in);
		
	}



	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if(version == CERTIFICATE_VERSION_1){
		return "Certificate [version=" + version + "\n" +
			   "  signerInfos:" + EncodeHelper.listToString(signerInfos, "SignerInfo ", true, 4)  + "\n" +
			   "  subjectInfo:\n" + 
			   "    " + subjectInfo.toString().replace("SubjectInfo ", "") + "\n" +
			   "  subjectAttributes:" + EncodeHelper.listToString(subjectAttributes, "SubjectAttribute ", true, 4) + "\n" +
			   "  validityRestrictions:" + EncodeHelper.listToString(validityRestrictions, "ValidityRestriction ", true, 4) + "\n" +
			   "  signature:" + ( signature != null ? "\n    " + signature.toString().replace("Signature ", "") : "none") + "\n" +
			   "]";
		}else{
			return "Certificate [version=" + version + "\n" +
				   "  signerInfo:\n" + 
				   "    " + signerInfos.get(0).toString().replace("SignerInfo ", "") + "\n" +
				   "  subjectInfo:\n" + 
				   "    " + subjectInfo.toString().replace("SubjectInfo ", "") + "\n" +
				   "  subjectAttributes:" + EncodeHelper.listToString(subjectAttributes, "SubjectAttribute ", true, 4) + "\n" +
				   "  validityRestrictions:" + EncodeHelper.listToString(validityRestrictions, "ValidityRestriction ", true, 4, new ValidityRestrictionToString()) + "\n" +
				   "  signature:" + ( signature != null ? "\n    " + signature.toString().replace("Signature ", "") : "none") + "\n" +
				   "]";
		}
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
	

	/**
	 * Help method for verifying signer info type of v2 certificate.
	 * @param signerInfoType the type to check
	 * @throws IllegalArgumentException in invalid type was given.
	 */
	private void checkSignerInfoType(SignerInfoType signerInfoType) throws IllegalArgumentException{
		if(signerInfoType == SignerInfoType.certificate ||
		   signerInfoType == SignerInfoType.certificate_chain){
			throw new IllegalArgumentException("Invalid signer info type for certificate version");
		}
	}

	@Override
	public Type getCertificateType() {
		return Type.EXPLICIT;
	}

	@Override
	public PublicKey getPublicKey(
			CryptoManager cryptoManager,
			AlgorithmIndicator alg,
			org.certificateservices.custom.c2x.common.Certificate signerCertificate,
			PublicKey signerPublicKey) throws InvalidKeySpecException,
			SignatureException, IllegalArgumentException {
		if(!(cryptoManager instanceof ITSCryptoManager)){
			throw new IllegalArgumentException("Error extracting public key from ETSI ITS certificate, related crypto manager must be a Ieee1609Dot2CryptoManager implementation.");
		}
		if(alg == null || alg.getAlgorithm().getSignature() == null){
			throw new IllegalArgumentException("Error extracting public key from certificate, and algorithm indicator specifying signature algorithm must be specified.");
		}
		ITSCryptoManager itsCryptoManager = (ITSCryptoManager) cryptoManager;
		
		return (PublicKey) itsCryptoManager.decodeEccPoint(alg, itsCryptoManager.getVerificationKey(this));
	}

	class ValidityRestrictionToString implements ToStringCallback{

		@Override
		public String toString(Object o) {
			if(o instanceof ValidityRestriction){
				return ((ValidityRestriction) o).toString(version);
			}
			return o.toString();
		}
		
	}
}
