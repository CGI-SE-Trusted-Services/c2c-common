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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;

import java.io.*;

/**
 * Class representing CertificateSubjectAttributes defined in ETSI TS 102 941 Base Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CertificateSubjectAttributes extends COERSequence {


	private static final long serialVersionUID = 1L;

	private static final int ID = 0;
	private static final int VALIDITYPERIOD = 1;
	private static final int REGION = 2;
	private static final int ASSURANCELEVEL = 3;
	private static final int APPPERMISSIONS = 4;
	private static final int CERTISSUEPERMISSIONS = 5;

	/**
	 * Constructor used when decoding
	 */
	public CertificateSubjectAttributes(){
		super(true,6);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public CertificateSubjectAttributes(CertificateId id,
                                        ValidityPeriod validityPeriod, GeographicRegion region, SubjectAssurance assuranceLevel,
                                        SequenceOfPsidSsp appPermissions, SequenceOfPsidGroupPermissions certIssuePermissions) throws IOException{
		super(true,6);
		init();

		if(appPermissions == null && certIssuePermissions == null){
			throw new IOException("Invalid CertificateSubjectAttributes one of appPermissions, certIssuePermissions must be present");
		}

		set(ID, id);
		set(VALIDITYPERIOD, validityPeriod);
		set(REGION, region);
		set(ASSURANCELEVEL, assuranceLevel);
		set(APPPERMISSIONS, appPermissions);
		set(CERTISSUEPERMISSIONS, certIssuePermissions);
	}

	/**
	 * Constructor decoding a ToBeSignedCertificate from an encoded byte array.
	 * @param encodedData byte array encoding of the ToBeSignedCertificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public CertificateSubjectAttributes(byte[] encodedData) throws IOException{
		super(true,6);
		init();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedData));
		decode(dis);
	}

	private void init() {
		addField(ID, true, new CertificateId(), null);
		addField(VALIDITYPERIOD, true, new ValidityPeriod(), null);
		addField(REGION, true, new GeographicRegion(), null);
		addField(ASSURANCELEVEL, true, new SubjectAssurance(), null);
		addField(APPPERMISSIONS, true, new SequenceOfPsidSsp(), null);
		addField(CERTISSUEPERMISSIONS, true, new SequenceOfPsidGroupPermissions(), null);
		
	}
	
	/**
	 * @return the id, required
	 */
	public CertificateId getId() {
		return (CertificateId) get(ID);
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


	@Override
	public String toString() {
		return 
		"CertificateSubjectAttributes [\n" +
	    "  id=" + ( getId() != null  ? getId().toString().replaceAll("CertificateId ", "") : "NONE") + "\n" +
	    "  validityPeriod=" + ( getValidityPeriod() != null  ? getValidityPeriod().toString().replaceAll("ValidityPeriod ", "") : "NONE") + "\n" +
	    "  region=" + ( getRegion() != null ? getRegion().toString().replaceAll("GeographicRegion ", "") : "NONE") + "\n" +
	    "  assuranceLevel=" + ( getAssuranceLevel() != null ? getAssuranceLevel().toString().replaceAll("SubjectAssurance ", "") : "NONE") + "\n" +
	    "  appPermissions=" + ( getAppPermissions() != null ? getAppPermissions().toString().replaceAll("SequenceOfPsidSsp ", "") : "NONE") + "\n" +
	    "  certIssuePermissions=" + ( getCertIssuePermissions() != null ? getCertIssuePermissions().toString().replaceAll("SequenceOfPsidGroupPermissions ", "") : "NONE") + "\n" +
	    "]";
		
	}
	
}
