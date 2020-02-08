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
package org.certificateservices.custom.c2x.etsits103097.v131.validator;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;

/**
 * Class containing all CTLService related constants used
 * to check permissions in certificate.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class CTLServicePermissions {

    /**
     * Current version of CTLService SSP Data.
     */
    public static final byte VERSION_1 = 1;

    /**
     * The certificate can be used to sign CTL containing the TLM entries.
     */
    public static final byte SIGN_TLM_ENTRIES = (byte) 0x80;

    /**
     * The certificate can be used to sign CTL containing the Root CA entries
     */
    public static final byte SIGN_ROOTCA_ENTRIES = (byte) 0x40;

    /**
     * The certificate can be used to sign CTL containing the EA entries
     */
    public static final byte SIGN_EA_ENTRIES = (byte) 0x20;

    /**
     * The certificate can be used to sign CTL containing the AA entries
     */
    public static final byte SIGN_AA_ENTRIES = (byte) 0x10;

    /**
     * The certificate can be used to sign CTL containing the DC entries
     */
    public static final byte SIGN_DC_ENTRIES = (byte) 0x08;

    /**
     * Help method to calculate a SSP Bitmap Permission of bits indicated
     * by the array of CtlEntryChoices.
     * @param entryTypes the set of CtlEntryChoices to create SSP Bitmap for.
     * @return a bitmap of given entry types.
     */
    public static byte getPermissions(CtlEntry.CtlEntryChoices[] entryTypes){
        byte retval = 0;
        for(CtlEntry.CtlEntryChoices entryType : entryTypes){
            retval |= getPermission(entryType);
        }
        return retval;
    }

    /**
     * Help method to get the corresponding SSP bit permission for given CtlEntryChoices entry type.
     * @param entryType the CtlEntryChoices entry to to get bitmap permission for.
     * @return the related bitmap permission.
     */
    public static byte getPermission(CtlEntry.CtlEntryChoices entryType){
        switch (entryType){
            case tlm:
                return SIGN_TLM_ENTRIES;
            case rca:
                return SIGN_ROOTCA_ENTRIES;
            case ea:
                return SIGN_EA_ENTRIES;
            case aa:
                return SIGN_AA_ENTRIES;
            case dc:
                return SIGN_DC_ENTRIES;
        }
        return 0;
    }

}
