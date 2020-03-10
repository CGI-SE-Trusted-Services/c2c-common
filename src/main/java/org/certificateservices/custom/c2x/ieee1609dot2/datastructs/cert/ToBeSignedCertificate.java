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

import org.certificateservices.custom.c2x.asn1.coer.COERNull;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;

/**
 * The fields in the ToBeSignedCertificate structure have the following meaning:
 * 
 * <li>id contains information that is used to identify the certificate holder if necessary.
 * <li>cracaId identifies the Certificate Revocation Authorization CA (CRACA) responsible for Certificate Revocation
 * Lists (CRLs) on which this certificate might appear. Use of the cracaId is specified in 5.1.3.The HashedId3 is
 * calculated with the whole-certificate hash algorithm, determined as described in 6.4.3.
 * <li>crlSeries represents the CRL series relevant to a particular Certificate Revocation Authorization CA (CRACA) on which the certificate might appear. Use of this field is specified in 5.1.3.
 * <li>validityPeriod contains the validity period of the certificate.
 * <li>region, if present, indicates the validity region of the certificate. If it is omitted the validity
 * region is indicated as follows:
 * <br>
 * -If enclosing certificate is self-signed, i.e. the choice indicated by the issuer field in the enclosing certificate structure is self, the certificate is valid worldwide.
 * <br>
 * -Otherwise, the certificate has the same validity region as the certificate that issued it.
 * <ul>
 * <li>assuranceLevel indicates the assurance level of the certificate holder.
 * <li>appPermissions indicates the permissions that the certificate holder has to sign application data with this certificate. A valid instance of appPermissions contains any particular Psid value in at most one entry.
 * <li>certIssuePermissions indicates the permissions that the certificate holder has to sign certificates with this certificate. A valid instance of this array contains no more than one entry whose psidSspRange field indicates all. If the array has multiple entries and one entry has its psidSspRange field indicate all, then the entry indicating all specifies the permissions for all PSIDs other than the ones explicitly specified in the other entries. See the descr iption of PsidGroupPermissions for further discussion.
 * <li>certRequestPermissions indicates the permissions that the certificate holder has to sign certificate requests with this certificate. A valid instance of this array contains no more than one entry whose psidSspRange field indicates all. If the array has multiple entries and one entry has its psidSspRange field indicate all, then the entry indicating all specifies the permissions for all PSIDs other than the ones explicitly specified in the other entries. See the description of PsidGroupPermissions for further discussion.
 * <li>canRequestRollover indicates that the certificate may be used to sign a request for another certificate with the same permissions. This field is provided for future use and its use is not defined in this version of this standard.
 * <li>encryptionKey contains a public key for encryption for which the certificate holder holds the corresponding private key.
 * <li>verifyKeyIndicator contains material that may be used to recover the public key that may be used to verify data signed by this certificate.
 * </ul>
 * <p>
 *     <b>Encoding considerations:</b> The encoding of toBeSigned which is input to the hash uses the compressed
 * form for all public keys and reconstruction values that are elliptic curve points: that is, those points (which
 * in this standard are all EccP256CurvePoints) indicate a choice of compressed-y-0 or compressedy-
 * 1. The encoding of the issuing certificate uses the compressed form for all public key and reconstruction
 * values and takes the r value of an ECDSA signature, which in this standard is an ECC
 * curve point, to be of type x-only.
 * For both implicit and explicit certificates, when the certificate is hashed to create or recover the public key
 * (in the case of an implicit certificate) or to generate or verify the signature (in the case of an explicit
 * certificate), the hash is Hash (Data input) || Hash (Signer identifier input), where:
 * <ul>
 * <li>Data input is the COER encoding of toBeSigned, canonicalized as described above.</li>
 * <li></li>Signer identifier input depends on the verification type, which in turn depends on the choice
 * indicated by issuer. If the choice indicated by issuer is self, the verification type is selfsigned
 * and the signer identifier input is the empty string. If the choice indicated by issuer is not
 * self, the verification type is certificate and the signer identifier input is the COER encoding of
 * the canonicalization per 6.4.3 of the certificate indicated by issuer.</li>
 * </ul>
 * In other words, for implicit certificates, the value H (CertU) in SEC 4, section 3, is for purposes of this
 * standard taken to be H [H (canonicalized ToBeSignedCertificate from the subordinate certificate) || H
 * (canonicalized entirety of issuer Certificate)]. See 5.3.2 for further discussion, including material
 * differences between this
 * </p>
 * <p>
 * <b>Critical information fields:</b>
 * <ul>
 * <li>If present, appPermissions is a critical information field as defined in 5.2.5. An
 * implementation that does not support the number of PsidSsp in appPermissions shall reject
 * the encrypted signed SPDU as invalid. A compliant implementation shall support
 * appPermissions fields containing at least eight entries.</li>
 * <li>If present, certIssuePermissions is a critical information field as defined in 5.2.5. An
 * implementation that does not support the number of PsidGroupPermissions in
 * certIssuePermissions shall reject the encrypted signed SPDU as invalid. A compliant
 * implementation shall support certIssuePermissions fields containing at least eight entries.</li>
 * <li>If present, certRequestPermissions is a critical information field as defined in 5.2.5. An
 * implementation that does not support the number of PsidGroupPermissions in
 * certRequestPermissions shall reject the encrypted signed SPDU as invalid. A compliant
 * implementation shall support certRequestPermissions fields containing at least eight
 * entries.</li>
 * </ul>
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
	public class ToBeSignedCertificate extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int ID = 0;
	private static final int CRACAID = 1;
	private static final int CRLSERIES = 2;
	private static final int VALIDITYPERIOD = 3;
	private static final int REGION = 4;
	private static final int ASSURANCELEVEL = 5;
	private static final int APPPERMISSIONS = 6;
	private static final int CERTISSUEPERMISSIONS = 7;
	private static final int CERTREQUESTPERMISSIONS = 8;
	private static final int CANREQUESTROLLOVER = 9;
	private static final int ENCRYPTIONKEY = 10;
	private static final int VERIFYKEYINDICATOR = 11;
	


	/**
	 * Constructor used when decoding
	 */
	public ToBeSignedCertificate() {
		super(true,12);
		try {
			init();
		}catch(IOException e){
			throw new RuntimeException("Error constructing ToBeSignedCertificate: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Constructor used when encoding
	 */
	public ToBeSignedCertificate(CertificateId id, HashedId3 cracaId, CrlSeries crlSeries,
			ValidityPeriod validityPeriod, GeographicRegion region, SubjectAssurance assuranceLevel,
			SequenceOfPsidSsp appPermissions, SequenceOfPsidGroupPermissions certIssuePermissions,
			SequenceOfPsidGroupPermissions certRequestPermissions, boolean canRequestRollover,
			PublicEncryptionKey encryptionKey, VerificationKeyIndicator verifyKeyIndicator) throws IOException{
		super(true,12);
		init();
		
		if(appPermissions == null && certIssuePermissions == null && certRequestPermissions == null){
			throw new IOException("Invalid ToBeSignedCertificate one of appPermissions, certIssuePermissions or certRequestPermissions must be present");
		}
		
		set(ID, id);
		set(CRACAID,cracaId);
		set(CRLSERIES, crlSeries);
		set(VALIDITYPERIOD, validityPeriod);
		set(REGION, region);
		set(ASSURANCELEVEL, assuranceLevel);
		set(APPPERMISSIONS, appPermissions);
		set(CERTISSUEPERMISSIONS, certIssuePermissions);
		set(CERTREQUESTPERMISSIONS, certRequestPermissions);
		if(canRequestRollover){
		  set(CANREQUESTROLLOVER, new COERNull());
		}
		set(ENCRYPTIONKEY, encryptionKey);
		set(VERIFYKEYINDICATOR, verifyKeyIndicator);
		
		
	}

	/**
	 * Constructor decoding a ToBeSignedCertificate from an encoded byte array.
	 * @param encodedData byte array encoding of the ToBeSignedCertificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public ToBeSignedCertificate(byte[] encodedData) throws IOException{
		super(true,12);
		init();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedData));
		decode(dis);
	}

	

	
	private void init() throws IOException{
		addField(ID, false, new CertificateId(), null);
		addField(CRACAID, false, new HashedId3(), null);
		addField(CRLSERIES, false, new CrlSeries(), null);
		addField(VALIDITYPERIOD, false, new ValidityPeriod(), null);
		addField(REGION, true, new GeographicRegion(), null);
		addField(ASSURANCELEVEL, true, new SubjectAssurance(), null);
		addField(APPPERMISSIONS, true, new SequenceOfPsidSsp(), null);
		addField(CERTISSUEPERMISSIONS, true, new SequenceOfPsidGroupPermissions(), null);
		addField(CERTREQUESTPERMISSIONS, true, new SequenceOfPsidGroupPermissions(), null);
		addField(CANREQUESTROLLOVER, true, new COERNull(), null);
		addField(ENCRYPTIONKEY, true, new PublicEncryptionKey(), null);
		addField(VERIFYKEYINDICATOR, false, new VerificationKeyIndicator(), null);
		
	}
	
	/**
	 * @return the id, required
	 */
	public CertificateId getId() {
		return (CertificateId) get(ID);
	}

	/**
	 * @return the cracaId, required
	 */
	public HashedId3 getCracaId() {
		return (HashedId3) get(CRACAID);
	}

	/**
	 * @return the crlSeries, required
	 */
	public CrlSeries getCrlSeries() {
		return (CrlSeries) get(CRLSERIES);
	}

	/**
	 * @return the validityPeriod, required
	 */
	public ValidityPeriod getValidityPeriod() {
		return (ValidityPeriod) get(VALIDITYPERIOD);
	}

	/**
	 * @return the region, optional
	 */
	public GeographicRegion getRegion() {
		return (GeographicRegion) get(REGION);
	}

	/**
	 * @return the assuranceLevel, optional
	 */
	public SubjectAssurance getAssuranceLevel() {
		return (SubjectAssurance) get(ASSURANCELEVEL);
	}

	/**
	 * @return the appPermissions, optional
	 */
	public SequenceOfPsidSsp getAppPermissions() {
		return (SequenceOfPsidSsp) get(APPPERMISSIONS);
	}

	/**
	 * @return the certIssuePermissions, optional
	 */
	public SequenceOfPsidGroupPermissions getCertIssuePermissions() {
		return (SequenceOfPsidGroupPermissions) get(CERTISSUEPERMISSIONS);
	}

	/**
	 * @return the certRequestPermissions, optional
	 */
	public SequenceOfPsidGroupPermissions getCertRequestPermissions() {
		return (SequenceOfPsidGroupPermissions) get(CERTREQUESTPERMISSIONS);
	}

	/**
	 * @return the canRequestRollover, optional
	 */
	public boolean isCanRequestRollover() {
		return get(CANREQUESTROLLOVER) != null;
	}

	/**
	 * @return the encryptionKey, optional
	 */
	public PublicEncryptionKey getEncryptionKey() {
		return (PublicEncryptionKey) get(ENCRYPTIONKEY);
	}

	/**
	 * @return the verifyKeyIndicator, required
	 */
	public VerificationKeyIndicator getVerifyKeyIndicator() {
		return (VerificationKeyIndicator) get(VERIFYKEYINDICATOR);
	}
	
	/**
	 * @param verificationKeyIndicator required
	 */
	public void setVerifyKeyIndicator(VerificationKeyIndicator verificationKeyIndicator) throws IOException{
		set(VERIFYKEYINDICATOR, verificationKeyIndicator);
	}
	
	/**
	 * Encodes the ToBeSignedCertificate as a byte array.
	 * 
	 * @return return encoded version of the ToBeSignedCertificate as a byte[] 
	 * @throws IOException if encoding problems of the data occurred.
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
		"ToBeSignedCertificate [\n" +
	    "  id=" + getId().toString().replaceAll("CertificateId ", "") + "\n" +
	    "  cracaId=" + getCracaId().toString().replaceAll("HashedId3 ", "") + "\n" +
	    "  crlSeries=" + getCrlSeries().toString().replaceAll("CrlSeries ", "") + "\n" +
	    "  validityPeriod=" + getValidityPeriod().toString().replaceAll("ValidityPeriod ", "") + "\n" +
	    "  region=" + ( getRegion() != null ? getRegion().toString().replaceAll("GeographicRegion ", "") : "NONE") + "\n" +
	    "  assuranceLevel=" + ( getAssuranceLevel() != null ? getAssuranceLevel().toString().replaceAll("SubjectAssurance ", "") : "NONE") + "\n" +
	    "  appPermissions=" + ( getAppPermissions() != null ? getAppPermissions().toString().replaceAll("SequenceOfPsidSsp ", "") : "NONE") + "\n" +
	    "  certIssuePermissions=" + ( getCertIssuePermissions() != null ? getCertIssuePermissions().toString().replaceAll("SequenceOfPsidGroupPermissions ", "") : "NONE") + "\n" +
	    "  certRequestPermissions=" + ( getCertRequestPermissions() != null ? getCertRequestPermissions().toString().replaceAll("SequenceOfPsidGroupPermissions ", "") : "NONE") + "\n" +
	    "  canRequestRollover=" + isCanRequestRollover() + "\n" +
	    "  encryptionKey=" + ( getEncryptionKey() != null ? getEncryptionKey().toString().replaceAll("PublicEncryptionKey ", "") : "NONE") + "\n" +
	    "  verifyKeyIndicator=" + getVerifyKeyIndicator().toString().replace("VerificationKeyIndicator ", "") + "\n" +
	    "]";
		
	}
	
}
