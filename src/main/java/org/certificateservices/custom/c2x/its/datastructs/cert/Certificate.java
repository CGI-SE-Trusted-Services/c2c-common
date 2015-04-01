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
import java.util.List;

import org.certificateservices.custom.c2x.its.datastructs.SerializationHelper;
import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;

/**
 * This structure defines how to encode a certificate.
 * <li> version specifies this certificate's version and shall be set to 1 for conformance with the present document.
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
public class Certificate implements StructSerializer {
	
	public static final int DEFAULT_CERTIFICATE_VERSION = 1;
	
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
	 * Main constructor for a certificate template without any signature attached and default version.
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
		this(DEFAULT_CERTIFICATE_VERSION, signerInfos, subjectInfo, subjectAttributes, validityRestrictions);		
	}
	
	/**
	 * Main constructor for a certificate with an attached signature.
	 *  
	 * @param version specifies this certificate's version.
	 * @param signerInfos information on this certificate's signer
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
	 */
	public Certificate(int version, 
			List<SignerInfo> signerInfos, 
			SubjectInfo subjectInfo, 
			List<SubjectAttribute> subjectAttributes,  
			List<ValidityRestriction> validityRestrictions,
			Signature signature){
		this(version, signerInfos, subjectInfo, subjectAttributes, validityRestrictions);
		this.signature = signature;
	}
	

	/**
	 * Constructor creating a certificate from an encoded byte array.
	 * @param encodedCert byte array encoding of the certificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public Certificate(byte[] encodedCert) throws IOException{
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedCert));
		deserialize(dis);
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
	public void serialize(DataOutputStream out) throws IOException {
		out.write(version);		
		SerializationHelper.encodeVariableSizeVector(out, signerInfos);
		subjectInfo.serialize(out);
		SerializationHelper.encodeVariableSizeVector(out, subjectAttributes);
		SerializationHelper.encodeVariableSizeVector(out, validityRestrictions);		
		if(signature != null){
			signature.serialize(out);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void deserialize(DataInputStream in) throws IOException {
		version = in.read();
		signerInfos = (List<SignerInfo>) SerializationHelper.decodeVariableSizeVector(in, SignerInfo.class);

		subjectInfo = new SubjectInfo();
		subjectInfo.deserialize(in);
		
		subjectAttributes = (List<SubjectAttribute>) SerializationHelper.decodeVariableSizeVector(in, SubjectAttribute.class);
		
		validityRestrictions = (List<ValidityRestriction>) SerializationHelper.decodeVariableSizeVector(in, ValidityRestriction.class);
				
		signature = new Signature();
		signature.deserialize(in);
		
	}



	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "Certificate [version=" + version + ", signerInfos="
				+ signerInfos + ", subjectInfo=" + subjectInfo
				+ ", subjectAttributes=" + subjectAttributes
				+ ", validityRestrictions=" + validityRestrictions
				+ ", signature=" + signature + "]";
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
		serialize(dos);
		return baos.toByteArray();		
	}
	

	

	
}
