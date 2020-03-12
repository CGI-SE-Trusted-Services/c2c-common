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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.Certificate;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BitmapSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BaseCertificateValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.DefaultSSPLookup;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.EmptyDefaultSSPLookup;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Permission validator for evaluating app and cert issue permissions of ETSI 103 097 Certificates.
 * <p>
 *     It also contains extra method to check specific permissions for the SecuredCertificateRequestService (623)
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class ETSI103097PermissionValidator extends BasePermissionValidator {

    /**
     * Constructor used for validators in a PKI with no known default SSP values. Initializes
     * itself with an EmptyDefaultSSPLookup.
     */
    public ETSI103097PermissionValidator(){
        super(new EmptyDefaultSSPLookup());
    }

    /**
     * Constructor used in PKIs with known default SSP values used when PSIDSSP contains empty SSP data.
     *
     * @param defaultSSPLookup lookup implementation of default SSP values for specific SSP and SSPRanges.
     */
    public ETSI103097PermissionValidator(DefaultSSPLookup defaultSSPLookup){
        super(defaultSSPLookup);
    }

    /**
     * Method to validate permissions in a certificate chain that starts with an end entity certificate. It will check
     * all permissions set in the certificate for the given end entity type.
     *
     * @param targetEndEntityType the target end entity type to validate.
     * @param certificateChain the certificate chain with end entity certificate first.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException if one of the specified parameters was invalid.
     * @throws InvalidCertificateException if certificate chain contained invalid permissions.
     */
    @Override
    public void checkPermissions(EndEntityType targetEndEntityType, Certificate[] certificateChain, boolean entireChain) throws BadArgumentException, InvalidCertificateException {
        checkPermissions(targetEndEntityType,0,certificateChain, entireChain);
    }

    /**
     * Special use-case method to validate permissions in a certificate chain that starts with a ca certificate. It will check
     * all permissions set in the certificate for the given end entity type.
     *
     * @param targetEndEntityType the target end entity type to validate.
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certificateChain the certificate chain with end entity certificate first.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException if one of the specified parameters was invalid.
     * @throws InvalidCertificateException if certificate chain contained invalid permissions.
     */
    @Override
    public void checkPermissions(EndEntityType targetEndEntityType, int chainLengthIndex, Certificate[] certificateChain, boolean entireChain) throws BadArgumentException, InvalidCertificateException {
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] ieee160CertChain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);

        if (ieee160CertChain.length > 1) {
            if(entireChain) {
                for (int i = 0; i < (ieee160CertChain.length - 1); i++) {
                    checkPermissions(targetEndEntityType, i + chainLengthIndex, ieee160CertChain[i], ieee160CertChain[i + 1]);
                }
            }else{
                checkPermissions(targetEndEntityType, chainLengthIndex, ieee160CertChain[0], ieee160CertChain[1]);
            }
        }
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     */
    public void checkCertServicePermissionInAppPermissions(byte ssPVersion, byte ssPPermissions,
                                                           Certificate[] certificateChain) throws InvalidCertificateException,
            BadArgumentException {
        checkBitmapAppPermission(ssPVersion,ssPPermissions,certificateChain,AvailableITSAID.SecuredCertificateRequestService.getValueAsLong(), "SecuredCertificateRequestService (623)");
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its CRLService (622) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use CRLServicePermissions.VERSION_ constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     */
    public void checkCRLServicePermissionInAppPermissions(byte ssPVersion, Certificate[] certificateChain)
            throws InvalidCertificateException, BadArgumentException {
        checkBitmapAppPermission(ssPVersion,null,certificateChain,AvailableITSAID.CRLService.getValueAsLong(),
                "CRLService (622)");
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its CTLService (624) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use CTLServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use CTLServicePermission constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     */
    public void checkCTLServicePermissionInAppPermissions(byte ssPVersion, byte ssPPermissions,
                                                          Certificate[] certificateChain) throws InvalidCertificateException, BadArgumentException {
        checkBitmapAppPermission(ssPVersion,ssPPermissions,certificateChain,AvailableITSAID.CTLService.getValueAsLong(), "CTLService (624)");
    }


    /**
     * Method to check if the first certificate in supplied chain have a specific certIssuePermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param endEntityType the end entity type to lookup
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certificateChain the certificate chain to lookup cert issuer permissions if the first certificate.
     * @throws IOException if one of the parameter contained invalid data.
     * @throws InvalidCertificateException if no given permissions was found in certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     */
    public void checkCertServicePermissionInIssuePermissions(byte ssPVersion, byte ssPPermissions,
                                                             EndEntityType endEntityType, int chainLengthIndex,
                                                             Certificate[] certificateChain)
            throws InvalidCertificateException, IOException, BadArgumentException {
        byte[] sspData = new byte[]{ssPVersion,ssPPermissions};
        if(certificateChain.length == 0){
            throw new InvalidCertificateException("Unable to check permissions for empty chain.");
        }
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] ieee160CertChain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);

        List<PsidGroupPermissions> applicablePsIdGroupPermissions = filterByEndEntityTypeAndChainLength(endEntityType, chainLengthIndex, ieee160CertChain[0].getToBeSigned().getCertIssuePermissions().getSequenceValues());
        long pSId = AvailableITSAID.SecuredCertificateRequestService.getValueAsLong();
        List<PsidSspRange> filteredPsidSspRange = filterPsidSspRangeByPSID(pSId,applicablePsIdGroupPermissions);

        try {
            checkBitmapSSP(pSId, new BitmapSsp(sspData), filteredPsidSspRange);
        }catch(InvalidCertificateException e){
            throw new InvalidCertificateException("Couldn't find issue permission for SecuredCertificateRequestService (623): " + Hex.toHexString(sspData) + " in certificate.");
        }
    }

    /**
     * Help method to check app and cert issue permission of an certificate against permissions in its issuer.
     * If certificate contains certRequestPermissions is InvalidCertificateException thrown since it is not
     * supported in ETSI 103097 PKIs.
     * @param endEntityType the end entity type to evaluate permissions for.
     * @param chainLength the current index in the chain evaulation, starts at 0 and is incremented.
     * @param certificate the certificate to check permissions for towards it issuer
     * @param issuer the issuer certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     * @throws InvalidCertificateException if certificate contained invalid permissions.
     */
    protected void checkPermissions(EndEntityType endEntityType, int chainLength,
                                    org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate,
                                    org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate issuer)
            throws BadArgumentException, InvalidCertificateException{
        checkAppPermissions(endEntityType,chainLength,certificate,issuer);
        checkCertIssuePermissions(endEntityType,chainLength,certificate,issuer);

        if(certificate.getToBeSigned().getCertRequestPermissions() != null){
            throw new InvalidCertificateException("Invalid certiifcate, certRequestPermissions is currently not supported during validation.");
        }
    }

    /**
     * General method to check if the first certificate in supplied chain have a specific appPermission set in
     * the specified itsaid service id using bitmap matching.
     *
     * @param sspData the SSP data to verify.
     * @param certificate the certificate to check permission.
     * @param itsAID it ITS AID Service id to check.
     * @param serviceName the name of the service used in error messages, if null will itsAID be used instead.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     */
    public void checkBitmapAppPermission(byte[] sspData, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, long itsAID, String serviceName) throws InvalidCertificateException, BadArgumentException {
        if(serviceName == null){
            serviceName = "ITS AID " + itsAID;
        }

        List<PsidSsp> servicePermissions = filterPsidSspByPSID(itsAID,certificate.getToBeSigned().getAppPermissions());
        for(PsidSsp servicePermission : servicePermissions){
            if(servicePermission.getSSP().getType() == ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp){
                byte[] bitmapSpp = servicePermission.getSSP().getBitmapSsp().getData();
                if(sspData.length != bitmapSpp.length){
                    throw new InvalidCertificateException("Invalid service permission for " + serviceName + ", provided SSPValue length doesn't match bitmap length in appPermissions.");
                }
                boolean foundMatch = true;
                for(int i=0; i < bitmapSpp.length; i++){
                    if((sspData[i] & bitmapSpp[i]) != sspData[i]){
                        foundMatch = false;
                        break;
                    }
                }
                if(foundMatch){
                    return;
                }
            }else{
                throw new InvalidCertificateException("Invalid service permission for " + serviceName + ", expected type bitmapSsp but the certificate contained opaque.");
            }
        }
        throw new InvalidCertificateException("Couldn't find permission for " + serviceName + ": " + Hex.toHexString(sspData) + " in certificate.");
    }

    /**
     * General method to check if the first certificate in supplied chain have a specific appPermission set in
     * the specified itsaid service id using opaque matching.
     *
     * @param sspData the SSP data to verify.
     * @param certificate the certificate to check permission.
     * @param itsAID it ITS AID Service id to check.
     * @param serviceName the name of the service used in error messages, if null will itsAID be used instead.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     */
    public void checkOpaqueAppPermission(byte[] sspData, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, long itsAID, String serviceName) throws InvalidCertificateException, BadArgumentException {
        if(serviceName == null){
            serviceName = "ITS AID " + itsAID;
        }

        List<PsidSsp> servicePermissions = filterPsidSspByPSID(itsAID,certificate.getToBeSigned().getAppPermissions());
        for(PsidSsp servicePermission : servicePermissions){
            if(servicePermission.getSSP().getType() == ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque){
                byte[] opaqueData = servicePermission.getSSP().getData();
                if(Arrays.equals(sspData, opaqueData)){
                    return;
                }
            }else{
                throw new InvalidCertificateException("Invalid service permission for " + serviceName + ", expected type bitmapSsp but the certificate contained opaque.");
            }
        }
        throw new InvalidCertificateException("Couldn't find permission for " + serviceName + ": " + Hex.toHexString(sspData) + " in certificate.");
    }

    /**
     * General method to check if the first certificate in supplied chain have a specific appPermission set in
     * the specified itsaid service id.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @param itsAID it ITS AID Service id to check.
     * @param serviceName the name of the service used in error messages, if null will itsAID be used instead.
     * @throws BadArgumentException if one of the parameter contained invalid data.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     */
    protected void checkBitmapAppPermission(byte ssPVersion, Byte ssPPermissions, Certificate[] certificateChain, long itsAID, String serviceName) throws InvalidCertificateException, BadArgumentException {
        byte[] sspData;
        if(ssPPermissions != null) {
            sspData = new byte[]{ssPVersion, ssPPermissions};
        }else{
            sspData = new byte[]{ssPVersion};
        }
        if(certificateChain.length == 0){
            throw new InvalidCertificateException("Unable to check permissions for empty chain.");
        }
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] ieee160CertChain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);
        checkBitmapAppPermission(sspData,ieee160CertChain[0],itsAID,serviceName);
    }

}
