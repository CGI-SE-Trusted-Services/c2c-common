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
package org.certificateservices.custom.c2x.ieee1609dot2.validator;

import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.common.validator.PermissionValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions;

import java.io.IOException;
import java.util.*;

/**
 * Base class containing help method for performing permission validation of Ieee1609 and ETSI 103097 certificates.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public abstract class BasePermissionValidator implements PermissionValidator {


    DefaultSSPLookup defaultSSPLookup;


    protected BasePermissionValidator(DefaultSSPLookup defaultSSPLookup){
        this.defaultSSPLookup = defaultSSPLookup;
    }

    /**
     * Help method to check app permission of an certificate against permissions in its issuer.
     * If certificate contains certRequestPermissions is InvalidCertificateException thrown since it is not
     * supported in ETSI 103097 PKIs.
     * @param endEntityType the end entity type to evaluate permissions for.
     * @param chainLength the current index in the chain evaulation, starts at 0 and is incremented.
     * @param certificate the certificate to check permissions for towards it issuer
     * @param issuer the issuer certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     * @throws InvalidCertificateException if certificate contained invalid permissions.
     */
    protected void checkAppPermissions(EndEntityType endEntityType, int chainLength, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate issuer) throws BadArgumentException, InvalidCertificateException{
        SequenceOfPsidGroupPermissions issuerCertIssuePermissions = issuer.getToBeSigned().getCertIssuePermissions();

        SequenceOfPsidSsp appPermissions = certificate.getToBeSigned().getAppPermissions();
        if(appPermissions!= null){
            checkForDuplicatePsid(appPermissions);
            for (Object next : appPermissions.getSequenceValues()) {
                if (next instanceof PsidSsp) {
                    PsidSsp psidSsp = (PsidSsp) next;
                    canIssueAppPermissions(endEntityType, chainLength, psidSsp, issuer);
                } else {
                    throw new InvalidCertificateException("Invalid SequenceOfPsidSsp in certificate appPermissions, only PsidSsp should be in sequence.");
                }
            }
        }
    }

    /**
     * Help method to check app permission of an certificate against permissions in its issuer.
     * If certificate contains certRequestPermissions is InvalidCertificateException thrown since it is not
     * supported in ETSI 103097 PKIs.
     *
     * @param endEntityType the end entity type to evaluate permissions for.
     * @param chainLength   the current index in the chain evaulation, starts at 0 and is incremented.
     * @param appPerm       PsidSsp the permission to lookup if the issuing certificate is authorized to issue.
     * @param issuer        the issuer certificate.
     * @throws InvalidCertificateException if certificate contained invalid permissions.
     */
    public void canIssueAppPermissions(EndEntityType endEntityType, int chainLength, PsidSsp appPerm, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate issuer) throws InvalidCertificateException {
        SequenceOfPsidGroupPermissions issuerCertIssuePermissions = issuer.getToBeSigned().getCertIssuePermissions();

        long pSId = appPerm.getPsid().getValueAsLong();
        ServiceSpecificPermissions ssp = appPerm.getSSP();
        if (appPerm.getSSP() == null) {
            ssp = defaultSSPLookup.getDefaultSSP(appPerm.getPsid());
        }
        if (ssp == null) {
            throw new InvalidCertificateException("No SSP data found for permission (Neither in certificate in default) with PSID " + pSId + ".");
        }
        List<PsidSspRange> matchingPssidSspRanges = filterPsidSspRangeByPSID(pSId, filterByEndEntityTypeAndChainLength(endEntityType, chainLength + 1, issuerCertIssuePermissions.getSequenceValues()));
        if (matchingPssidSspRanges.size() == 0 &&
                hasAllPermissions(endEntityType, chainLength + 1, issuerCertIssuePermissions)) {
            return;
        }
        if (ssp.getType() == ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque) {
            checkOpaqueSSP(pSId, ssp.getData(), matchingPssidSspRanges);
        } else {
            checkBitmapSSP(pSId, ssp.getBitmapSsp(), matchingPssidSspRanges);
        }

    }

    /**
     * Help method to check cert issue permission of an certificate against permissions in its issuer.
     * If certificate contains certRequestPermissions is InvalidCertificateException thrown since it is not
     * supported in ETSI 103097 PKIs.
     * @param endEntityType the end entity type to evaluate permissions for.
     * @param chainLength the current index in the chain evaulation, starts at 0 and is incremented.
     * @param certificate the certificate to check permissions for towards it issuer
     * @param issuer the issuer certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     * @throws InvalidCertificateException if certificate contained invalid permissions.
     */
    protected void checkCertIssuePermissions(EndEntityType endEntityType, int chainLength, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate issuer) throws BadArgumentException, InvalidCertificateException{
        SequenceOfPsidGroupPermissions issuerCertIssuePermissions = issuer.getToBeSigned().getCertIssuePermissions();

        SequenceOfPsidGroupPermissions certIssuePermissions = certificate.getToBeSigned().getCertIssuePermissions();
        if(certIssuePermissions != null){
            List<PsidGroupPermissions>  psidGroupPermissionList = filterByEndEntityTypeAndChainLength(endEntityType,chainLength,certIssuePermissions.getSequenceValues());
            for (PsidGroupPermissions psidGroupPermissions : psidGroupPermissionList) {
                SequenceOfPsidSspRange sequenceOfPsidSspRange = (SequenceOfPsidSspRange) psidGroupPermissions.getSubjectPermissions().getValue();
                for(Object next : sequenceOfPsidSspRange.getSequenceValues()) {
                    if(next instanceof PsidSspRange){
                        PsidSspRange psidSspRange = getPsidSspRangeWithDefault((PsidSspRange) next);
                        long pSId = psidSspRange.getPsid().getValueAsLong();
                        SspRange sspRange = psidSspRange.getSSPRange();
                        if(sspRange == null){
                            sspRange = defaultSSPLookup.getDefaultSSPRange(psidSspRange.getPsid());
                        }
                        if(sspRange == null){
                            throw new InvalidCertificateException("No SSPRange data found for certificate (Neither in certificate in default) with PSID " + pSId + ".");
                        }
                        List<PsidSspRange> matchingPssidSspRanges = filterPsidSspRangeByPSID(pSId, filterByEndEntityTypeAndChainLength(endEntityType, chainLength+1, issuerCertIssuePermissions.getSequenceValues()));
                        if(matchingPssidSspRanges.size() == 0 &&
                                !hasAllPermissions(endEntityType,chainLength,issuerCertIssuePermissions) &&
                                !hasAllPermissions(endEntityType,chainLength,certIssuePermissions)){
                            throw new InvalidCertificateException("No matching issuer permissions for PSID " + pSId + " exists in issuer certificate.");
                        }
                        if(psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.all){
                            checkForSSPRangeWithAll(pSId,matchingPssidSspRanges);
                        }else if (psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.opaque) {
                            checkOpaqueSSPRange(pSId, psidSspRange.getSSPRange(), matchingPssidSspRanges);
                        }else {
                            checkBitmapSSPRange(pSId, psidSspRange.getSSPRange().getBitmapSspRange(), matchingPssidSspRanges);
                        }
                    }else{
                        throw new InvalidCertificateException("Invalid SequenceOfPsidSspRange in certificate appPermissions, only PsidSspRange should be in sequence.");
                    }
                }
            }

        }
    }


    /**
     * Help method to check that no duplicate PSID was found in a SequenceOfPsidSsp structure.
     * @param sequenceOfPsidSsp the sequence to check
     * @throws InvalidCertificateException if a duplicate PSID found in structure.
     */
    protected void checkForDuplicatePsid(SequenceOfPsidSsp sequenceOfPsidSsp) throws InvalidCertificateException {
        Set<Long> existingPsid = new HashSet<>();
        List<COEREncodable> sequence = sequenceOfPsidSsp.getSequenceValuesAsList();
        for(Object next: sequence){
            assert next instanceof PsidSsp : "Invalid SequenceOfPsidSsp, object in list was not PsidSsp";
            PsidSsp psidSsp = (PsidSsp) next;
            Long psIdValue = psidSsp.getPsid().getValueAsLong();
            if(existingPsid.contains(psIdValue)){
                throw new InvalidCertificateException("Invalid sequenceOfPsidSsp found in certificate permissions, duplicate PSID " + psIdValue + " found.");
            }
            existingPsid.add(psIdValue);
        }
    }


    /**
     * Method to check that there for a all permissioned SSP Range in matching Pssid Ranges of issuer.
     * @param pSId the related PSID
     * @param matchingPssidSspRanges a list of all PsidSspRange having given PSID.
     * @throws InvalidCertificateException if no SSPRange with all found in issuer.
     */
    protected void checkForSSPRangeWithAll(long pSId, List<PsidSspRange> matchingPssidSspRanges) throws InvalidCertificateException{
        for(PsidSspRange sspRange : matchingPssidSspRanges){
            if(sspRange.getSSPRange().getType() == SspRange.SspRangeChoices.all){
                return;
            }
        }
        throw new InvalidCertificateException("No issuer permission with SspRange of type all found for PSID " + pSId + ".");
    }


    /**
     * Method that check if a certificate has all permissions and if so returns true, unless there is more than one
     * all permission, then is InvalidCertificateException thrown.
     * @param endEntityType the target end entity type of permissions to lookup.
     * @param chainLength the cirrent chain length to look up permissions for, 0 for end entity 1 for it's issuer and up.
     * @param sequenceOfPsidGroupPermissions a sequence of PsidGroupPermissions to check if all permissions exists.
     * @return true if certificate have one all permissions.
     * @throws InvalidCertificateException  if more than one all permissions exists.
     */
    protected boolean hasAllPermissions(EndEntityType endEntityType, int chainLength, SequenceOfPsidGroupPermissions sequenceOfPsidGroupPermissions) throws InvalidCertificateException{
        List<PsidGroupPermissions> filteredGroupPermissions = filterByEndEntityTypeAndChainLength(endEntityType,chainLength,sequenceOfPsidGroupPermissions.getSequenceValues());
        int numberOfAllPermissions = 0;
        for(PsidGroupPermissions  psidGroupPermissions : filteredGroupPermissions){
            if(psidGroupPermissions.getSubjectPermissions().getType() == SubjectPermissions.SubjectPermissionsChoices.all){
                numberOfAllPermissions++;
            }
        }
        return numberOfAllPermissions > 0;
    }

    /**
     * Method to filter out all PsidSppRange for a specific psid, it traverses through all PsidGroupPermissions in the
     * list and only selects items.
     * @param psid the psid to filter by.
     * @param psidGroupPermissions  List of psidGroupPermsissions that have been filtered by filterByEndEntityTypeAndChainLength before
     *                              this call.
     * @return List of PsidSspRange with specified psid
     * @throws InvalidCertificateException if subjectPermissions contains sequence of SequenceOfPsidSspRange not containing PsidSspRange objects.
     */
    protected List<PsidSspRange> filterPsidSspRangeByPSID(long psid, List<PsidGroupPermissions> psidGroupPermissions) throws InvalidCertificateException{
        List<PsidSspRange> retval = new ArrayList<>();
        for(PsidGroupPermissions permissions : psidGroupPermissions){
            SubjectPermissions subjectPermissions = permissions.getSubjectPermissions();
            if(subjectPermissions.getType() == SubjectPermissions.SubjectPermissionsChoices.explicit){
                SequenceOfPsidSspRange sequenceOfPsidSspRange = (SequenceOfPsidSspRange) subjectPermissions.getValue();
                for(Object next : sequenceOfPsidSspRange.getSequenceValuesAsList()){
                    if(next instanceof PsidSspRange){
                        PsidSspRange psidSspRange = (PsidSspRange) next;
                        if(psidSspRange.getPsid().getValueAsLong() == psid){
                            retval.add(getPsidSspRangeWithDefault(psidSspRange));
                        }
                    }else{
                        throw new InvalidCertificateException("Invalid SequenceOfPsidSspRange in certificate, only PsidSspRange should be in sequence.");
                    }
                }
            }
        }

        return retval;
    }

    /**
     * Method that filters out a sequence of PsidSsp and returns a list of PsidSsp with matching PSID only.
     * @param psid the psid to filter.
     * @param sequenceOfPsidSsp sequence of PsidSsp to filter.
     * @return a list of matching PsidSsp, never null.
     * @throws InvalidCertificateException if encoding of certificate was invalid, i.e SequenceOfPsidSsp didn't contain PsidSsp.
     */
    protected List<PsidSsp> filterPsidSspByPSID(long psid, SequenceOfPsidSsp sequenceOfPsidSsp) throws InvalidCertificateException{
        List<PsidSsp> retval = new ArrayList<>();
        if(sequenceOfPsidSsp != null) {
            COEREncodable[] psidSpps = sequenceOfPsidSsp.getSequenceValues();
            for (Object next : psidSpps) {
                if(next instanceof PsidSsp) {
                    PsidSsp psidSsp = (PsidSsp) next;
                    if(psidSsp.getPsid().getValueAsLong() == psid){
                        retval.add(psidSsp);
                    }
                }else{
                    throw new InvalidCertificateException("Invalid SequenceOfPsidSsp in certificate, only PsidSsp should be in sequence.");
                }
            }
        }

        return retval;
    }

    /**
     * Method that filter out PsidGroupPermissions that have a specified end entity type and within the chain length
     * specified.
     * @param endEntityType the end entity type (i.e. app or enrol) that should be matched.
     * @param chainLength the chain length that should be within minChainDepth and minChainDepth + chainDepthRange.
     * @param psidGroupPermissions the array of psidGroupPermissions from certificate.
     * @return a list of matching PsidGroupPermissions never null
     * @throws InvalidCertificateException if encoding of certificate was invalid, i.e array of psidGroupPermissions didn't contain PsidGroupPermissions.
     */
    protected List<PsidGroupPermissions> filterByEndEntityTypeAndChainLength(EndEntityType endEntityType, int chainLength, COEREncodable[] psidGroupPermissions) throws InvalidCertificateException{
        List<PsidGroupPermissions> retval = new ArrayList<>();
        if(psidGroupPermissions != null) {
            for (Object next :psidGroupPermissions){
                if(!(next instanceof PsidGroupPermissions)){
                    throw new InvalidCertificateException("Invalid SequenceOfPsidGroupPermissions in cert, value was not PsidGroupPermissions.");
                }
                PsidGroupPermissions permissions = (PsidGroupPermissions) next;
                if(endEntityType.isEnroll() && !permissions.getEEType().isEnroll()){
                    continue;
                }
                if(endEntityType.isApp() && !permissions.getEEType().isApp()){
                    continue;
                }
                // The length is permitted to be (a) greater than or equal to minChainLength certificates
                if(chainLength < permissions.getMinChainDepth()){
                    continue;
                }
                // (b) less than or equal to minChainLength + chainLengthRange certificates.
                if( chainLength >  (permissions.getMinChainDepth() + permissions.getChainDepthRange())){
                    continue;
                }
                retval.add(permissions);
            }
        }
        return retval;
    }

    /**
     * Method to verify that a given SSP data matches permissions in specified list of PsidSspRange using SSP type opaque.
     *
     * @param pSId the related PSID
     * @param sspData the sspData to match against value in certificate.
     * @param psidSspRanges list of matching psidSspRanges, all PsidSspRange must contain specified psID.
     * @throws InvalidCertificateException if no permission was found or psidSspRanges contained invalid SSPRangeType.
     */
    protected void checkOpaqueSSP(long pSId, byte[] sspData, List<PsidSspRange> psidSspRanges) throws InvalidCertificateException{
        for(PsidSspRange psidSspRange : psidSspRanges){
            if(psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.all){
                return;
            }
            if(psidSspRange.getSSPRange().getType()  == SspRange.SspRangeChoices.opaque){
                for(Object next : psidSspRange.getSSPRange().getOpaqueData().getSequenceValues()){
                    if(next instanceof COEROctetStream){
                        COEROctetStream octetStream = (COEROctetStream) next;
                        // The sspRange field in P indicates opaque and one of the entries in opaque is an OCTET
                        // STRING of length 0.
                        if(sspData == null && octetStream.getData().length == 0){
                            return;
                        }
                        //The sspRange field in P indicates opaque and one of the entries in opaque is an OCTET
                        //    STRING of length 0.
                        if(Arrays.equals(sspData,octetStream.getData())){
                            return;
                        }
                    }
                }
            }else{
                throw new InvalidCertificateException("Invalid PsidSsp Permissions for PSID " + pSId + ", issuer SSPRange is of type bitmapSspRange, not expected opaque");
            }
        }
        throw new InvalidCertificateException("Invalid PsidSsp Permissions for PSID " + pSId + ", no matching octet stream found in issuer.");
    }

    /**
     * Method to check the SSP Range of type opaque agains a list of psidSspRanges
     * @param pSId the pSId of service to verify permissions for.
     * @param sspRange the SSP Range to check.
     * @param psidSspRanges list of matching PsidSspRange in issuer certificate, all in list must have specified psId.
     * @throws InvalidCertificateException
     */
    protected void checkOpaqueSSPRange(long pSId, SspRange sspRange, List<PsidSspRange> psidSspRanges) throws InvalidCertificateException{
        for(Object nextSsp : sspRange.getOpaqueData().getSequenceValues()) {
            if (nextSsp instanceof COEROctetStream) {
                COEROctetStream sspOctetStream = (COEROctetStream) nextSsp;
                byte[] sspData = sspOctetStream.getData();
                for (PsidSspRange psidSspRange : psidSspRanges) {
                    if(psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.all){
                        return;
                    }
                    if (psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.opaque) {
                        boolean foundMatch = false;
                        for (Object next : psidSspRange.getSSPRange().getOpaqueData().getSequenceValues()) {
                            if (next instanceof COEROctetStream) {
                                COEROctetStream octetStream = (COEROctetStream) next;
                                //The issuing certificate SspRange is of type opaque and all of the entries in the
                                //subordinate certificate’s SspRange exactly match an entry in the issuing certificate’s
                                //SspRange.
                                if (Arrays.equals(sspData, octetStream.getData())) {
                                    foundMatch = true;
                                    break;
                                }
                            }
                        }
                        if(!foundMatch){
                            throw new InvalidCertificateException("Invalid PsidSspRange for PSID: " + pSId + " could not find matching permissions in issuer certificate.");
                        }
                    } else {
                        throw new InvalidCertificateException("Invalid PsidSspRange Permissions for PSID " + pSId + ", issuer SSPRange is of type bitmapSspRange, not expected opaque");
                    }
                }
            } else {
                throw new InvalidCertificateException("Invalid SspRange Permissions for PSID " + pSId + ", certificate SSPRange is of type bitmapSspRange, not expected opaque");
            }
        }
    }


    /**
     * Method to check bitmap SSP Range value against a set of matching PsIDSSPRanges in issuer certificate.
     * @param pSId the pSId of service to verify permissions for.
     * @param certBitmapSspRange the bitmapSSPRange to verify against issuers permissions.
     * @param matchingPsidSspRanges list of matching PsidSspRange in issuer certificate, all in list must have specified psId.
     * @throws InvalidCertificateException if certificate was invalid or didn't have permissions.
     */
    protected void checkBitmapSSPRange(long pSId, BitmapSspRange certBitmapSspRange, List<PsidSspRange> matchingPsidSspRanges) throws InvalidCertificateException{

        boolean foundMatch = false;
        byte[] bitmaskP = certBitmapSspRange.getSspBitMask();
        byte[] sspValueP = certBitmapSspRange.getSspValue();

        if(matchingPsidSspRanges != null) {
            for (PsidSspRange psidSspRange : matchingPsidSspRanges) {
                    if(psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.all){
                        foundMatch = true;
                        break;
                    }
                    if(psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.opaque){
                        throw new InvalidCertificateException("Invalid PsidGroupPermissions for PSID " + pSId + ", issuer SSPRange is of type opaque, not expected bitmapSspRange.");
                    }
                    BitmapSspRange issuerBitmapSspRange = psidSspRange.getSSPRange().getBitmapSspRange();
                    byte[] bitmaskR = issuerBitmapSspRange.getSspBitMask();
                    byte[] sspValueR = issuerBitmapSspRange.getSspValue();

                    if(bitmaskP.length != bitmaskR.length){
                        throw new InvalidCertificateException("Invalid PsidGroupPermissions for PSID " + pSId + ", bitmaps in certificate have different length.");
                    }

                    boolean allBytesValid = true;
                    for(int i=0;i< bitmaskR.length;i++) {
                        if((bitmaskP[i] & bitmaskR[i]) != bitmaskR[i]){
                            allBytesValid = false;
                            break;
                        }
                        if((sspValueP[i] & bitmaskR[i]) != (sspValueR[i] & bitmaskR[i])){
                            allBytesValid = false;
                            break;
                        }
                    }
                    if(allBytesValid) {
                        foundMatch = true;
                    }
                    break;
                }
        }
        if(!foundMatch){
            throw new InvalidCertificateException("Invalid PsidGroupPermissions for PSID " + pSId + ", No matching PsidGroupPermissions found in issuer certificate.");
        }
    }

    /**
     * Method to check bitmap SSP value agains a set of matching PsIDSSPRanges in issuer certificate.
     * @param pSId hte pSId of service to verify permissions for.
     * @param certBitmapSsp the bitmapSSP to verify against issuers permissions.
     * @param matchingPsIdRange list of matching PsidSspRange in issuer certificate, all in list must have specified psId.
     * @throws InvalidCertificateException if certificate was invalid or didn't have permissions.
     */
    protected void checkBitmapSSP(long pSId, BitmapSsp certBitmapSsp, List<PsidSspRange> matchingPsIdRange) throws InvalidCertificateException{

        boolean foundMatch = false;
        byte[] sspValueA = certBitmapSsp.getData();

        if(matchingPsIdRange != null) {
            for (PsidSspRange psidSspRange : matchingPsIdRange) {
                if(psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.all){
                    foundMatch = true;
                    break;
                }
                if(psidSspRange.getSSPRange().getType() == SspRange.SspRangeChoices.opaque){
                    throw new InvalidCertificateException("Invalid PsidSspRange for PSID " + pSId + ", issuer SSPRange is of type opaque, not expected bitmapSspRange.");
                }
                BitmapSspRange issuerBitmapSspRange = psidSspRange.getSSPRange().getBitmapSspRange();
                byte[] bitmaskP = issuerBitmapSspRange.getSspBitMask();
                byte[] sspValueP = issuerBitmapSspRange.getSspValue();

                if(bitmaskP.length != sspValueA.length){
                    throw new InvalidCertificateException("Invalid PsidSspRange for PSID " + pSId + ", bitmap in certificate have different length.");
                }

                boolean allBytesValid = true;
                for(int i=0;i< bitmaskP.length;i++) {
                    if((sspValueA[i] & bitmaskP[i]) != (sspValueP[i] & bitmaskP[i])){
                        allBytesValid = false;
                    }
                }
                if(allBytesValid) {
                    foundMatch = true;
                }
                break;
            }
        }
        if(!foundMatch){
            throw new InvalidCertificateException("Invalid PsidGroupPermissions for PSID " + pSId + ", No matching PsidGroupPermissions found in issuer certificate.");
        }
    }

    private PsidSspRange getPsidSspRangeWithDefault(PsidSspRange psidSspRange) throws InvalidCertificateException{
        SspRange sspRange = psidSspRange.getSSPRange();
        if(sspRange == null){
            sspRange = defaultSSPLookup.getDefaultSSPRange(psidSspRange.getPsid());
        }
        if(sspRange == null){
            throw new InvalidCertificateException("No SSPRange data found for certificate (Neither in certificate in default) with PSID " + psidSspRange.getPsid().getValueAsLong() + ".");
        }
        try {
            return new PsidSspRange(psidSspRange.getPsid(), sspRange);
        }catch(IOException e){
            throw new InvalidCertificateException(e.getMessage(),e);
        }
    }


}
