package org.certificateservices.custom.c2x.common.validator;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CTL;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

/**
 * Interface for a CTL Validator verifying that the CTL itself is valid and returns all
 * valid certificates entries of full and delta CTL combined.
 *
 * @author Philip Vendil 2020-02-04
 */
public interface CTLValidator {

    /**
     * Method that verifies and validates a CTL and returns a certStore of all valid cert entries
     * from given full CTL and optionally delta CTL.
     * <p>
     *     The method will build a chain for the CTL from the set of trust anchors.
     * </p>
     *
     *
     * The following checks is done in the CTL.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>CTL validity</li>
     *     <li>Issuing Certificate has permissions to issue CTLs</li>
     *
     * </ul>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param fullCTL the full CTL to verify.
     * @param deltaCTL the delta CTL to verify, use null if no delta CTL is available.
     * @param checkDate the date to check validity of CRL and its certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @throws BadArgumentException if one of the parameters where invalid.
     * @throws InvalidCTLException if CTL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    Map<HashedId8,Certificate> verifyAndValidate(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL, Date checkDate,
                                                 GeographicRegion checkRegion, Map<HashedId8, Certificate> trustStore,
                                                 boolean entireChain, CtlEntry.CtlEntryChoices[] ctlTypes)
            throws BadArgumentException, InvalidCTLException, InvalidCertificateException, NoSuchAlgorithmException,
            CertificateRevokedException;


    /**
     * Method that verifies and validates a CTL and returns a certStore of all valid cert entries
     * from given full CTL and optionally delta CTL.
     * <p>
     *     The method will build a chain for the CTL from the set of trust anchors.
     * </p>
     *
     *
     * The following checks is done in the CTL.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>CTL validity</li>
     *     <li>Issuing Certificate has permissions to issue CTLs</li>
     *
     * </ul>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param fullCTL the full CTL to verify.
     * @param deltaCTL the delta CTL to verify, use null if no delta CTL is available.
     * @param checkDate the date to check validity of CRL and its certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param certStore a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @throws BadArgumentException if one of the parameters where invalid.
     * @throws InvalidCTLException if CTL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    Map<HashedId8,Certificate> verifyAndValidate(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL, Date checkDate, GeographicRegion checkRegion,
                                                 Map<HashedId8, Certificate> certStore,
                                                 Map<HashedId8, Certificate> trustStore,
                                                 boolean entireChain,
                                                 CtlEntry.CtlEntryChoices[] ctlTypes)
            throws BadArgumentException, InvalidCTLException, InvalidCertificateException, NoSuchAlgorithmException,
            CertificateRevokedException;

}
