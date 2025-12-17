package scratch.anne;

import java.lang.reflect.Field;
import java.util.List;
import java.util.ArrayList;
import java.io.IOException;

import org.opensha.sra.vulnerability.AbstractVulnerability;
import org.opensha.sra.vulnerability.models.SimpleVulnerability;
import org.opensha.sra.vulnerability.models.curee.caltech.CureeCaltechWoodFrame;
import org.opensha.commons.data.function.AbstractDiscretizedFunc;
import org.opensha.commons.data.function.ArbitrarilyDiscretizedFunc;
import org.opensha.sra.gui.LossEstimationApplication;

/**
 * Utility class for fetching and modifying vulnerability objects for the
 * LossEstimationApplication.
 * <p>
 * This class adapts Hazus SimpleVulnerability instances to a format
 * functionally similar to Curee vulnerabilities, and updates DEM matrices.
 * It uses reflection to access and modify private fields in SimpleVulnerability.
 * </p>
 * <p>
 * The use of reflection is a hack, in lieu of fixing the way that the servlet
 * accesses the Hazus vulnerabilities.
 * </p>
 * <p>
 * The Curee vulnerabilities are also updated to use dynamic generation of the DF_DEM
 * values and the associated probabilities in the DEM.
 * </p>
 */
public class fetchModifiedHazusVulnerabilities {

    /**
     * Fetches vulnerabilities from the LossEstimationApplication and converts them
     * to a unified format compatible with DEM computations.
     *
     * @return a List of modified AbstractVulnerability objects
     * @throws IOException if fetching vulnerabilities fails
     */
    public static List<AbstractVulnerability> getModifiedVulnerabilities() throws IOException {
        List<AbstractVulnerability> vulnerabilities = LossEstimationApplication.fetchVulns();
        List<AbstractVulnerability> modifiedVulnerabilities = new ArrayList<AbstractVulnerability>();

        for (AbstractVulnerability vuln : vulnerabilities) {
            if (vuln instanceof CureeCaltechWoodFrame) {
                // Modify CUREE-Caltech vulnerabilities directly
                modifiedVulnerabilities.add(partialToModifiedCureeVulnerability(vuln));

            } else if (vuln instanceof SimpleVulnerability) {
                // Remove entries with zero coefficient of variation
                shortenSimpleVulnerabilitySkipZeroCov((SimpleVulnerability) vuln);
                // Convert SimpleVulnerability to HazusAsCureeVulnerability format
                HazusAsCureeVulnerability partial = setHazusToPartialCureeVulnerability((SimpleVulnerability) vuln);
                // Build DEM and finalize
                modifiedVulnerabilities.add(partialToModifiedCureeVulnerability(partial));
            }
        }
        return modifiedVulnerabilities;
    }

    /**
     * Converts a partial vulnerability into a fully modified vulnerability
     * with a DEM matrix.
     *
     * @param vuln the vulnerability to modify (either a HazusAsCureeVulnerability or a CureeCaltechWoodFrame)
     * @return the modified vulnerability with DEM values set
     * @throws IllegalArgumentException if the vulnerability type is unexpected
     */
    private static AbstractVulnerability partialToModifiedCureeVulnerability(AbstractVulnerability vuln) {
        double[] DEM_DFs = getDamageFactorsForDEM();
        double[] imls;
        double[] DF;
        double[] COVDF;

        if (vuln instanceof HazusAsCureeVulnerability) {
            HazusAsCureeVulnerability h = (HazusAsCureeVulnerability) vuln;
            h.setDEM_DFs(DEM_DFs);
            imls = h.getIMLValues();
            DF = h.getDFArray();
            COVDF = h.getCOVDFArray();
            // Build DEM matrix: rows = DEM_DFs, columns = IMLs
            h.setDEM(buildDEMMatrix(imls, DF, COVDF, DEM_DFs));
            return h;

        } else if (vuln instanceof CureeCaltechWoodFrame) {
            CureeCaltechWoodFrame c = (CureeCaltechWoodFrame) vuln;
            imls = c.getIMLValues();
            DF = c.getDFArray();
            COVDF = c.getCOVDFArray();
            c.setDEM_DFs(DEM_DFs);
            // Build DEM matrix: rows = DEM_DFs, columns = IMLs
            c.setDEM(buildDEMMatrix(imls, DF, COVDF, DEM_DFs));
            return c;
        }

        throw new IllegalArgumentException("Unexpected vulnerability type: " + vuln.getClass().getName());
    }

    /**
     * Builds the damage exceedance matrix (DEM) for a given vulnerability.
     *
     * @param imls array of intensity measure levels
     * @param DF array of mean damage factors
     * @param COVDF array of coefficients of variation
     * @param DEM_DFs array of DEM damage factor thresholds
     * @return a 2D array representing the DEM matrix (rows = DEM_DFs, columns = IMLs)
     */
    private static double[][] buildDEMMatrix(double[] imls, double[] DF, double[] COVDF, double[] DEM_DFs) {
        double[][] DEM = new double[DEM_DFs.length][imls.length];
        for (int i = 0; i < imls.length; i++) {
            // Create lognormal distribution from mean and coefficient of variation
            LogNormalFunctions logNorm = LogNormalFunctions.fromMeanAndCov(DF[i], COVDF[i]);
            for (int j = 0; j < DEM_DFs.length; j++) {
                // DEM[j][i] = P(Damage > DEM_DFs[j] | IML[i])
                // Equivalent to 1 - CDF at DEM threshold
                DEM[j][i] = 1 - logNorm.cdf(DEM_DFs[j]);
            }
        }
        return DEM;
    }

    /**
     * Converts a SimpleVulnerability instance into a HazusAsCureeVulnerability.
     * This is necessary because DF and COV values are not directly accessible when
     * they are returned by the servlet.
     *
     * @param vuln the SimpleVulnerability instance
     * @return a new HazusAsCureeVulnerability containing the same IM, DF, and COV values
     */
    private static HazusAsCureeVulnerability setHazusToPartialCureeVulnerability(SimpleVulnerability vuln) {
        
	    double[] imls = vuln.getIMLValues();
	    double[] DF = new double[imls.length];
	    double[] COVDF = new double[imls.length];
	    double period = vuln.getPeriod();
	    
	    // use the functions that are accessible in the SimpleVulnerability 
	    // to recreate the inaccessible DF and COVDF arrays
        AbstractDiscretizedFunc vulnerabilityFunction = vuln.getVulnerabilityFunc();
        AbstractDiscretizedFunc covFunction = vuln.getCOVFunction();
	    
        for (int i = 0; i < imls.length; i++) {
            DF[i] = vulnerabilityFunction.getY(imls[i]);
            COVDF[i] = covFunction.getY(imls[i]);
        }


        return new HazusAsCureeVulnerability(
            vuln.getName(),
            vuln.getShortName(),
            vuln.getIMT(),
            period,
            imls,
            DF,
            COVDF
        );
    }

    /**
     * Updates a SimpleVulnerability by removing all iml values for which the coefficient of
     * variation is zero.
     * <p>
     * This method uses reflection to access and modify private fields in SimpleVulnerability.
     * It also rebuilds the vulnerability and covariance functions.
     * </p>
     * 
     * <p>
     * This approach is a hack based on what is currently fetched and created from the Hazus
     * files, via the servlet. Ideally, that initial reading of the file would already create 
     * the desired vulnerability, rather than needing to do any of these modifications.
     * </p>
     *
     * @param vuln the SimpleVulnerability to modify
     */
    public static void shortenSimpleVulnerabilitySkipZeroCov(SimpleVulnerability vuln) {
        try {
            ArrayList imlsList = (ArrayList) getFieldFromClassHierarchy(vuln, "im_levels").get(vuln);
            ArrayList dfList   = (ArrayList) getFieldFromClassHierarchy(vuln, "mdfVals").get(vuln);
            ArrayList covList  = (ArrayList) getFieldFromClassHierarchy(vuln, "covVals").get(vuln);

            int size = covList.size();
            ArrayList imlsNew = new ArrayList();
            ArrayList dfNew   = new ArrayList();
            ArrayList covNew  = new ArrayList();

            for (int i = 0; i < size; i++) {
                double cov = ((Double) covList.get(i)).doubleValue();
                // Only keep entries with non-zero COV
                if (cov != 0) {
                    imlsNew.add(imlsList.get(i));
                    dfNew.add(dfList.get(i));
                    covNew.add(covList.get(i));
                }
            }

            // Update fields via reflection
            getFieldFromClassHierarchy(vuln, "im_levels").set(vuln, imlsNew);
            getFieldFromClassHierarchy(vuln, "mdfVals").set(vuln, dfNew);
            getFieldFromClassHierarchy(vuln, "covVals").set(vuln, covNew);

            // rebuild vulnerability function
            Field vulnFuncField = getFieldFromClassHierarchy(vuln, "vulnFunc");
            AbstractDiscretizedFunc vulnFunc = new ArbitrarilyDiscretizedFunc();
            for (int i = 0; i < imlsNew.size(); i++) {
                vulnFunc.set(((Double) imlsNew.get(i)).doubleValue(),
                             ((Double) dfNew.get(i)).doubleValue());
            }
            vulnFuncField.set(vuln, vulnFunc);

            // rebuild cov function
            Field covFuncField = getFieldFromClassHierarchy(vuln, "covFunc");
            AbstractDiscretizedFunc covFunc = new ArbitrarilyDiscretizedFunc();
            for (int i = 0; i < imlsNew.size(); i++) {
                covFunc.set(((Double) imlsNew.get(i)).doubleValue(),
                             ((Double) covNew.get(i)).doubleValue());
            }
            covFuncField.set(vuln, covFunc);

        } catch (Exception e) {
            throw new RuntimeException("Failed to update SimpleVulnerability arrays/functions", e);
        }
    }

    /**
     * Finds a declared field in an object's class or its superclasses.
     *
     * @param obj the object whose class hierarchy to search
     * @param fieldName the name of the field to find
     * @return the Field object
     * @throws NoSuchFieldException if the field is not found in the hierarchy
     */
    private static Field getFieldFromClassHierarchy(Object obj, String fieldName) throws NoSuchFieldException {
        Class clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field f = clazz.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }

    /**
     * Generates an array of damage factor thresholds for building the DEM matrix.
     * 
     * The start, increment, and end points (1e-6, 1.0, 1.2) are consistent with those
     * hardcoded in the Curee vulnerabilities
     *
     * @return array of damage factors
     */
    public static double[] getDamageFactorsForDEM() {
        return generateDamageFactorsForDEM(1e-6, 1.0, 1.2);
    }

    /**
     * Generates a geometrically spaced array of values from start to end.
     *
     * @param start the starting value
     * @param end the maximum value
     * @param ratio the geometric ratio between consecutive values
     * @return array of values
     */
    private static double[] generateDamageFactorsForDEM(double start, double end, double ratio) {
        List values = new ArrayList();
        for (double x = start; x <= end; x *= ratio) {
            // Add values spaced geometrically by ratio
            values.add(new Double(x));
        }
        double[] arr = new double[values.size()];
        for (int i = 0; i < values.size(); i++) arr[i] = ((Double) values.get(i)).doubleValue();
        return arr;
    }

    /**
     * Test method to fetch and display the modified vulnerabilities.
     * 
     * was initially used for debugging by printing various fields in 
     * the modified Hazus and Curee vulnerabilities
     *
     * @param args not used
     * @throws IOException if fetching vulnerabilities fails
     */
    public static void main(String[] args) throws IOException {
        List<AbstractVulnerability> vulnerabilities = getModifiedVulnerabilities();
        for (int i = 0; i < vulnerabilities.size(); i++) {
            System.out.println("Fetched " + vulnerabilities.get(i).getShortName());
        }
    }
}
