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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumerationType;

/**
 * Class representing enumeration AuthorizationValidationResponseCode defined in ETSI TS 102 941 Authorization
 * Validation Types
 * @author Philip Vendil, p.vendil@cgi.com
 */
public enum AuthorizationValidationResponseCode implements COEREnumerationType  {
    ok,
    cantparse, // valid for any structure
    badcontenttype, // not encrypted, not signed, not permissionsverificationrequest
    imnottherecipient, // the "recipients" of the outermost encrypted data doesn't include me
    unknownencryptionalgorithm, // either kexalg or contentencryptionalgorithm
    decryptionfailed, // works for ECIES-HMAC and AES-CCM
    invalidaa, // the AA certificate presented is invalid/revoked/whatever
    invalidaasignature, // the AA certificate presented can't validate the request signature
    wrongea, // the encrypted signature doesn't designate me as the EA
    unknownits, // can't retrieve the EC/ITS in my DB
    invalidsignature, // signature verification of the request by the EC fails
    invalidencryptionkey, // signature is good, but the responseEncryptionKey is bad
    deniedpermissions, // requested permissions not granted
    deniedtoomanycerts, // parallel limit
        deniedrequest, // any other reason?
}
