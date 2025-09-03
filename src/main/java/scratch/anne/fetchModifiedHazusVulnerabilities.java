package scratch.anne;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.io.IOException;

import org.opensha.sra.vulnerability.AbstractVulnerability;
import org.opensha.sra.vulnerability.models.SimpleVulnerability;
import org.opensha.sra.vulnerability.models.curee.caltech.CureeCaltechWoodFrame;
import org.opensha.commons.data.function.AbstractDiscretizedFunc;
import org.opensha.commons.data.function.ArbitrarilyDiscretizedFunc;
import org.opensha.sra.gui.LossEstimationApplication;



public class fetchModifiedHazusVulnerabilities {
	
	private static double[] imls;
	private static double[] DF;
	private static double[] COVDF;

    public static List<AbstractVulnerability> getModifiedVulnerabilities() throws IOException {
        List<AbstractVulnerability> vulnerabilities = LossEstimationApplication.fetchVulns();

        List<AbstractVulnerability> modifiedAsCureeVulnerabilities = new ArrayList<>();
        for (AbstractVulnerability vuln : vulnerabilities) {
            if (vuln instanceof CureeCaltechWoodFrame) {
//                System.out.println("CUREE-Caltech vulnerability: " + vuln.getShortName());
                CureeCaltechWoodFrame partialvuln = ((CureeCaltechWoodFrame)vuln);
//                CureeCaltechWoodFrame modifiedvuln = partialvuln;
                AbstractVulnerability modifiedvuln = partialToModifiedCureeVulnerability(vuln);
                modifiedAsCureeVulnerabilities.add(modifiedvuln);
//                System.out.println("DEM Matrix: " + Arrays.deepToString(modifiedvuln.getDEMMatrix()));
            } 
            else if (vuln instanceof SimpleVulnerability) {
//                System.out.println("modified Simple vulnerability: " + vuln.getShortName());
            	shortenSimpleVulnerabilitySkipZeroCov((SimpleVulnerability)vuln);
                HazusAsCureeVulnerability partialvuln = setHazusToPartialCureeVulnerability(((SimpleVulnerability)vuln));
                AbstractVulnerability modifiedvuln = partialToModifiedCureeVulnerability(partialvuln);
                modifiedAsCureeVulnerabilities.add(modifiedvuln);
//                System.out.println("DEM Matrix: " + Arrays.deepToString(modifiedvuln.getDEMMatrix()));
            } 
//            else {
//                throw new IllegalArgumentException(
//                    "Unexpected vulnerability type: " + vuln.getClass().getName()
//                );
//            }
        }
        return modifiedAsCureeVulnerabilities;
    }

        
//    private static HazusAsCureeVulnerability partialToModifiedCureeVulnerability(HazusAsCureeVulnerability vuln) {
//    	
//    	double[] DEM_DFs = getDamageFactorsForDEM();
//    	vuln.setDEM_DFs(DEM_DFs);
//    	
//    	double[][] DEM = new double[DEM_DFs.length][imls.length];
//    	
//    	for (int i = 0; i < imls.length; i++) {
//    		LogNormalFunctions logNorm = LogNormalFunctions.fromMeanAndCov(DF[i], COVDF[i]);
//    		for (int j = 0; j < DEM_DFs.length; j++) {
//    			DEM[j][i] = 1 - logNorm.cdf(DEM_DFs[j]);
//    		}
//    	}
//    	
//    	
////    	System.out.println("DEM Matrix: " + Arrays.deepToString(DEM));
//    	vuln.setDEM(DEM);
//    	
//    	return vuln;
//    }
    
    
    private static AbstractVulnerability partialToModifiedCureeVulnerability(AbstractVulnerability vuln) {
        double[] DEM_DFs = getDamageFactorsForDEM();

        double[] imls;
        double[] DF;
        double[] COVDF;

        // Determine type and get appropriate arrays
        if (vuln instanceof HazusAsCureeVulnerability) {
        	HazusAsCureeVulnerability h = (HazusAsCureeVulnerability) vuln;
            h.setDEM_DFs(DEM_DFs);
            imls = h.getIMLValues();
            DF = h.getDFArray();
            COVDF = h.getCOVDFArray();

            double[][] DEM = buildDEMMatrix(imls, DF, COVDF, DEM_DFs);
            h.setDEM(DEM);
            return h;

        } else if (vuln instanceof CureeCaltechWoodFrame) {
            // Example: adapt these accessors to the Curee class
        	CureeCaltechWoodFrame c = (CureeCaltechWoodFrame) vuln;
            imls = c.getIMLValues();
            DF = c.getDFArray();
            COVDF = c.getCOVDFArray();

            double[][] DEM = buildDEMMatrix(imls, DF, COVDF, DEM_DFs);

            c.setDEM_DFs(DEM_DFs);
            c.setDEM(DEM);
            
            // setting the DEM to zero is a quick check to make sure the hardcoded CUREE dem is overridden
//            double[][] zeroDEM = new double[DEM.length][DEM[0].length]; // all entries default to 0.0
//            c.setDEM(zeroDEM);
            
            System.out.println("Curee updated");
            
            
            return c;

        } else {
            throw new IllegalArgumentException("Unexpected vulnerability type: " + vuln.getClass().getName());
        }
    }
    
    
    /**
     * Build the DEM matrix: rows = DEM_DFs, columns = IMLs
     */
    private static double[][] buildDEMMatrix(double[] imls, double[] DF, double[] COVDF, double[] DEM_DFs) {
        double[][] DEM = new double[DEM_DFs.length][imls.length];
        for (int i = 0; i < imls.length; i++) {
            LogNormalFunctions logNorm = LogNormalFunctions.fromMeanAndCov(DF[i], COVDF[i]);
            for (int j = 0; j < DEM_DFs.length; j++) {
                DEM[j][i] = 1 - logNorm.cdf(DEM_DFs[j]);
            }
        }
        return DEM;
    }

    
    private static HazusAsCureeVulnerability setHazusToPartialCureeVulnerability(AbstractVulnerability vuln) {
    	String im_type = vuln.getIMT();
        double[] imlsExtra = vuln.getIMLValues();
//        int n_imls = imlsExtra.length - 1;
        int n_imls = imlsExtra.length;
        imls = new double[n_imls];
        DF = new double[n_imls];
        COVDF = new double[n_imls];

        AbstractDiscretizedFunc vulnerabilityFunction =
            ((SimpleVulnerability)vuln).getVulnerabilityFunc();
        AbstractDiscretizedFunc covFunction =
            ((SimpleVulnerability)vuln).getCOVFunction();

        for (int i = 0; i < n_imls; i++) {
        	imls[i] = imlsExtra[i];
            DF[i] = vulnerabilityFunction.getY(imls[i]);
            COVDF[i] = covFunction.getY(imls[i]);
        }

        return new HazusAsCureeVulnerability(
            vuln.getName(),
            vuln.getShortName(),
            vuln.getIMT(),
            imls,
            DF,
            COVDF
        );
    }
    
    
    public static void shortenSimpleVulnerabilitySkipZeroCov(SimpleVulnerability vuln) {
        try {
            // --- Helper to get ArrayList<Double> field ---
            @SuppressWarnings("unchecked")
            ArrayList<Double> imlsList = (ArrayList<Double>) getFieldFromClassHierarchy(vuln, "im_levels").get(vuln);
            @SuppressWarnings("unchecked")
            ArrayList<Double> dfList   = (ArrayList<Double>) getFieldFromClassHierarchy(vuln, "mdfVals").get(vuln);
            @SuppressWarnings("unchecked")
            ArrayList<Double> covList  = (ArrayList<Double>) getFieldFromClassHierarchy(vuln, "covVals").get(vuln);

            // --- Convert to double[] ---
            double[] imlsOld = imlsList.stream().mapToDouble(Double::doubleValue).toArray();
            double[] dfOld   = dfList.stream().mapToDouble(Double::doubleValue).toArray();
            double[] covOld  = covList.stream().mapToDouble(Double::doubleValue).toArray();

            // --- Count valid entries ---
            int validCount = 0;
            for (double c : covOld) if (c != 0) validCount++;

            // --- Build new arrays keeping only valid entries ---
            double[] imlsNew = new double[validCount];
            double[] dfNew   = new double[validCount];
            double[] covNew  = new double[validCount];

            int idx = 0;
            for (int i = 0; i < covOld.length; i++) {
                if (covOld[i] != 0) {
                    imlsNew[idx] = imlsOld[i];
                    dfNew[idx]   = dfOld[i];
                    covNew[idx]  = covOld[i];
                    idx++;
                }
            }

            // --- Convert back to ArrayList<Double> ---
            ArrayList<Double> imlsNewList = new ArrayList<>();
            ArrayList<Double> dfNewList   = new ArrayList<>();
            ArrayList<Double> covNewList  = new ArrayList<>();

            for (int i = 0; i < validCount; i++) {
                imlsNewList.add(imlsNew[i]);
                dfNewList.add(dfNew[i]);
                covNewList.add(covNew[i]);
            }

            // --- Set the fields ---
            getFieldFromClassHierarchy(vuln, "im_levels").set(vuln, imlsNewList);
            getFieldFromClassHierarchy(vuln, "mdfVals").set(vuln, dfNewList);
            getFieldFromClassHierarchy(vuln, "covVals").set(vuln, covNewList);

            // --- Rebuild vulnerabilityFunc ---
            Field vulnFuncField = getFieldFromClassHierarchy(vuln, "vulnFunc");
            vulnFuncField.setAccessible(true);
            AbstractDiscretizedFunc vulnFunc = new ArbitrarilyDiscretizedFunc();
            for (int i = 0; i < validCount; i++) {
                vulnFunc.set(imlsNew[i], dfNew[i]);
            }
            vulnFuncField.set(vuln, vulnFunc);

            // --- Rebuild covFunc ---
            Field covFuncField = getFieldFromClassHierarchy(vuln, "covFunc");
            covFuncField.setAccessible(true);
            AbstractDiscretizedFunc covFunc = new ArbitrarilyDiscretizedFunc();
            for (int i = 0; i < validCount; i++) {
                covFunc.set(imlsNew[i], covNew[i]);
            }
            covFuncField.set(vuln, covFunc);

//            System.out.println("SimpleVulnerability updated, removed entries where covdf==0. New length: " + validCount);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to update SimpleVulnerability arrays/functions", e);
        }
    }

    // --- Helper to find field in class hierarchy ---
    private static Field getFieldFromClassHierarchy(Object obj, String fieldName) throws NoSuchFieldException {
        Class<?> clazz = obj.getClass();
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

    
    public static double[] getDamageFactorsForDEM() {
    	double start = 1e-6;
    	double end = 1;
    	double ratio = 1.2;
    			
        return generateDamageFactorsForDEM(start, end, ratio);
    }
    
    private static double[] generateDamageFactorsForDEM(double start, double end, double ratio) {
    	List<Double> values = new ArrayList<>();
        for (double x = start; x <= end; x *= ratio) values.add(x);
        return values.stream().mapToDouble(Double::doubleValue).toArray();
    }
    
    // various print statements used in testing
    public static void main(String[] args) throws IOException {
    	List<AbstractVulnerability> vulnerabilities = getModifiedVulnerabilities();
    	for (AbstractVulnerability vuln : vulnerabilities) {
    		System.out.println("Fetched " + vuln.getShortName());
//    		System.out.println("im type: " + vuln.getIMT());
//    		System.out.println("imtl levels: " + Arrays.toString(vuln.getIMTValues()));
//    		System.out.println("imtl n levels: " + vuln.getIMLValues().length);
    		
    		
//            if (vuln instanceof CureeCaltechWoodFrame) {
//            	System.out.println("DEM Matrix: " + Arrays.deepToString(((CureeCaltechWoodFrame)vuln).getDEMMatrix()));
//                System.out.println("CUREE-Caltech vulnerability: " + vuln.getShortName());
//                System.out.println("df values: " + Arrays.toString(((CureeCaltechWoodFrame)vuln).getDFArray()));
//        		System.out.println("cov values: " + Arrays.toString(((CureeCaltechWoodFrame)vuln).getCOVDFArray()));    
//            } 
//            if (vuln instanceof HazusAsCureeVulnerability) {
//           	System.out.println("DEM Matrix: " + Arrays.deepToString(((HazusAsCureeVulnerability)vuln).getDEMMatrix()));
//               System.out.println("Hazus-Curee vulnerability: " + vuln.getShortName());
//               System.out.println("im type: " + vuln.getIMT());
//               System.out.println("df values: " + Arrays.toString(((HazusAsCureeVulnerability)vuln).getDFArray()));
//       		System.out.println("cov values: " + Arrays.toString(((HazusAsCureeVulnerability)vuln).getCOVDFArray()));  
//      		System.out.println("dem_dfs: " + Arrays.toString(((HazusAsCureeVulnerability)vuln).getDEMDFVals()));  
//      		System.out.println(vuln);
//      		System.out.println(((HazusAsCureeVulnerability)vuln).getDEMDimensions());
//        		
//          } 
//            else {
//                throw new IllegalArgumentException(
//                    "Unexpected vulnerability type: " + vuln.getClass().getName()
//                );
//            }
//        }
 		
    	}
    }
}

