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
package org.certificateservices.custom.c2x.etsits103097.v131.cert;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId.CertificateIdChoices.binaryId;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId.CertificateIdChoices.linkageData;

/**
 * A certificate contained in a secure data structure shall be of type EtsiTs103097Certificate as defined in
 * annex A, which corresponds to a single ExplicitCertificate as defined in IEEE Std 1609.2 [1] clause 6.4.6,
 * with the constraints defined in this clause.
 * <p>
 * The component toBeSigned of the type EtsiTs103097Certificate shall be of type
 * ToBeSignedCertificate as defined in IEEE Std 1609.2 [1] clause 6.4.8 and constrained as follows:
 * <ul>
 *     <li>The component id of type CertificateId constrained to choice type name or none.</li>
 *     <li>The component cracaId set to 000000'H.</li>
 *     <li>The component crlSeries set to 0'D.</li>
 *     <li>The component validityPeriod with no further constraints.</li>
 *     <li>The component region of type GeographicRegion as defined in IEEE Std 1609.2 [1], present or absent
 * according to the specification of certificate profiles in clause 7.</li>
 *     <li>The component assuranceLevel of type SubjectAssurance, as defined in IEEE Std 1609.2 [1],
 * present or absent according to the specification of certificate profiles in clause 7.</li>
 *     <li>The component appPermissions of type SequenceOfPsidSsp as defined in IEEE Std 1609.2 [1],
 * present or absent according to the specification of certificate profiles in clause 7.</li>
 *     <li>The component certIssuePermissions of type SequenceOfPsidGroupPermissions, as defined
 * in IEEE Std 1609.2 [1], present or absent according to the specification of certificate profiles in clause 7.</li>
 *     <li>At least one of the components appPermissions and certIssuePermissions shall be present.</li>
 *     <li>The component certRequestPermissions absent.</li>
 *     <li>The component canRequestRollover absent.</li>
 *     <li>The component encryptionKey of type PublicEncryptionKey as defined in IEEE Std 1609.2 [1],
 * present or absent according to the specification of certificate profiles in clause 7.</li>
 *     <li>The component verifyKeyIndicator of type VerificationKeyIndicator as defined in IEEE
 * Std 1609.2 [1], present and constrained to the choice verificationKey..</li>
 * </ul>
 * </p>
 * <p>
 *     The component signature of EtsiTs103097Certificate shall be of type Signature as defined in IEEE
 * Std 1609.2 [1] clause 6.3.28 and shall contain the signature, calculated by the signer identified in the issuer component,
 * as defined in IEEE Std 1609.2 [1] clauses 6.3.29, 6.3.29a and 5.3.1.
 * </p>
 *
 */
public class EtsiTs103097Certificate extends Certificate {

    /**
     * Constructor used when decoding
     */
    public EtsiTs103097Certificate(){
        super();
    }

    /**
     * Constructor used when encoding explicit certificate
     */
    public EtsiTs103097Certificate(int version, IssuerIdentifier issuer,
                       ToBeSignedCertificate toBeSigned, Signature signature) throws IllegalArgumentException{
        super(version,issuer, toBeSigned,signature);
        if(toBeSigned.getId() != null && (toBeSigned.getId().getType() == linkageData ||
           toBeSigned.getId().getType() == binaryId)){
            throw new IllegalArgumentException("Invalid id type in toBeSigned field of EtsiTs103097Certificate: " + toBeSigned.getId().getType());
        }
        if(toBeSigned.getCertRequestPermissions() != null){
            throw new IllegalArgumentException("Invalid toBeSigned field of EtsiTs103097Certificate, field certRequestPermissions cannot be set.");
        }
        if(toBeSigned.isCanRequestRollover()){
            throw new IllegalArgumentException("Invalid toBeSigned field of EtsiTs103097Certificate, field canRequestRollover cannot be set.");
        }
    }

    /**
     * Constructor used when encoding explicit certificate of default version
     */
    public EtsiTs103097Certificate(IssuerIdentifier issuer,
                       ToBeSignedCertificate toBeSigned,Signature signature) throws IllegalArgumentException{
        this(CURRENT_VERSION, issuer, toBeSigned,signature);
    }

    @Override
    public String toString() {
        return super.toString().replace("Certificate ","EtsiTs103097Certificate ");
    }

}
