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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumerationType;

/**
 * Class representing enumeration EnrollmentResponseCode defined in ETSI TS 102 941 Enrollment Types
 * @author Philip Vendil, p.vendil@cgi.com
 */
public enum EnrollmentResponseCode implements COEREnumerationType  {
    ok,
    cantparse, // valid for any structure
    badcontenttype, // not encrypted, not signed, not enrolmentrequest
    imnottherecipient, // the "recipients" doesn’t include me
    unknownencryptionalgorithm, // either kexalg or contentencryptionalgorithm
    decryptionfailed, // works for ECIES-HMAC and AES-CCM
    unknownits, // can’t retrieve the ITS from the itsId
    invalidsignature, // signature verification of the request fails
    invalidencryptionkey, // signature is good, but the responseEncryptionKey is bad
    baditsstatus, // revoked, not yet active
    incompleterequest, // some elements are missing
    deniedpermissions, // requested permissions are not granted
    invalidkeys, // either the verification_key of the encryption_key is bad
    deniedrequest, // any other reason?
}
