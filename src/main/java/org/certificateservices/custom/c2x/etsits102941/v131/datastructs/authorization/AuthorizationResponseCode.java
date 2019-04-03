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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumerationType;

/**
 * Class representing enumeration AuthorizationResponseCode defined in ETSI TS 102 941 Authorization Types
 * @author Philip Vendil, p.vendil@cgi.com
 */
public enum AuthorizationResponseCode implements COEREnumerationType  {
    ok,
    // // ITS->AA
    its_aa_cantparse, //// valid for any structure
    its_aa_badcontenttype, // not encrypted, not signed, not authorizationrequest
    its_aa_imnottherecipient, // the recipients of the outermost encrypted data doesnt include me
    its_aa_unknownencryptionalgorithm, // either kexalg or contentencryptionalgorithm
    its_aa_decryptionfailed, // works for ECIES-HMAC and AES-CCM
    its_aa_keysdontmatch, // HMAC keyTag verification fails
    its_aa_incompleterequest, // some elements are missing
    its_aa_invalidencryptionkey, // the responseEncryptionKey is bad
    its_aa_outofsyncrequest, // signingTime is outside acceptable limits
    its_aa_unknownea, // the EA identified by eaId is unknown to me
    its_aa_invalidea, // the EA certificate is revoked
    its_aa_deniedpermissions, // I, the AA, deny the requested permissions
  // AA->EA
    aa_ea_cantreachea, // the EA is unreachable (network error?)
  // EA->AA
    ea_aa_cantparse, // valid for any structure
    ea_aa_badcontenttype, // not encrypted, not signed, not authorizationrequest
    ea_aa_imnottherecipient, // the recipients of the outermost encrypted data doesnt include me
    ea_aa_unknownencryptionalgorithm, // either kexalg or contentencryptionalgorithm
    ea_aa_decryptionfailed, // works for ECIES-HMAC and AES-CCM
    // TODO: to be continued...
    invalidaa, // the AA certificate presented is invalid/revoked/whatever
    invalidaasignature, // the AA certificate presented cant validate the request signature
    wrongea, // the encrypted signature doesnt designate me as the EA
    unknownits, // cant retrieve the EC/ITS in my DB
    invalidsignature, // signature verification of the request by the EC fails
    invalidencryptionkey, // signature is good, but the key is bad
    deniedpermissions, // permissions not granted
    deniedtoomanycerts // parallel limit
}
