package scratch.anne;

import org.apache.commons.math3.distribution.LogNormalDistribution;
import java.util.Arrays;

/**
 * Utility class for working with the log-normal distribution.
 * <p>
 * Wraps Apache Commons Math's {@link LogNormalDistribution} and provides
 * convenience methods to compute PDF, CDF, and quantiles for both
 * single values and arrays of values.
 * </p>
 * <p>
 * Provides constructors from either the parameters of the underlying normal distribution
 * (μ and σ) or from the arithmetic mean and coefficient of variation (CoV) of the
 * lognormal distribution.
 * </p>
 * 
 * @author Anne Hulsey
 * @version 2025-09-03
 */
public class LogNormalFunctions {

    private final LogNormalDistribution logNorm;

    // -------- Constructors --------

    /**
     * Creates a log-normal distribution from μ (log-scale mean) and σ (log-scale standard deviation).
     * <p>
     * These are the parameters of the <em>underlying normal distribution</em>:
     * <ul>
     *   <li>μ = mean of ln(X)</li>
     *   <li>σ = standard deviation of ln(X)</li>
     * </ul>
     * Note: These are <strong>not</strong> the mean and standard deviation of the lognormal distribution itself.
     * </p>
     *
     * @param mu mean of the underlying normal distribution (log of the median)
     * @param sigma standard deviation of the underlying normal distribution
     */
    public LogNormalFunctions(double mu, double sigma) {
        this.logNorm = new LogNormalDistribution(mu, sigma);
    }

    /**
     * Creates a log-normal distribution from the arithmetic mean and coefficient of variation (CoV).
     * <p>
     * Converts mean and CoV of the lognormal distribution into μ and σ of the underlying normal:
     * <ul>
     *   <li>σ = sqrt(ln(1 + cov²))</li>
     *   <li>μ = ln(mean) − ½·σ²</li>
     * </ul>
     * </p>
     *
     * @param mean arithmetic mean of the lognormal distribution
     * @param cov coefficient of variation of the lognormal distribution
     * @return a new {@link LogNormalFunctions} instance
     */
    public static LogNormalFunctions fromMeanAndCov(double mean, double cov) {
        double sigma = Math.sqrt(Math.log(1 + cov * cov));
        double mu = Math.log(mean) - 0.5 * sigma * sigma;
        return new LogNormalFunctions(mu, sigma);
    }

    // -------- Array versions --------

    /**
     * Returns the cumulative distribution function (CDF) for an array of values.
     *
     * @param xValues array of input values
     * @return array of CDF values
     */
    public double[] cdf(double[] xValues) {
        double[] results = new double[xValues.length];
        for (int i = 0; i < xValues.length; i++) {
            results[i] = cdf(xValues[i]);
        }
        return results;
    }

    /**
     * Returns the probability density function (PDF) for an array of values.
     *
     * @param xValues array of input values
     * @return array of PDF values
     */
    public double[] pdf(double[] xValues) {
        double[] results = new double[xValues.length];
        for (int i = 0; i < xValues.length; i++) {
            results[i] = pdf(xValues[i]);
        }
        return results;
    }

    /**
     * Returns the quantiles (inverse CDF) for an array of probabilities.
     *
     * @param pValues array of probabilities in [0,1]
     * @return array of quantile values
     */
    public double[] quantile(double[] pValues) {
        double[] results = new double[pValues.length];
        for (int i = 0; i < pValues.length; i++) {
            results[i] = quantile(pValues[i]);
        }
        return results;
    }

    // -------- Single-value versions --------

    /**
     * Returns the cumulative distribution function (CDF) at the given value.
     *
     * @param x input value
     * @return probability that a random variable X ≤ x
     */
    public double cdf(double x) {
        return logNorm.cumulativeProbability(x);
    }

    /**
     * Returns the probability density function (PDF) at the given value.
     *
     * @param x input value
     * @return probability density at x
     */
    public double pdf(double x) {
        return logNorm.density(x);
    }

    /**
     * Returns the quantile (inverse CDF) for the given probability.
     *
     * @param p probability in [0,1]
     * @return x such that P(X ≤ x) = p
     */
    public double quantile(double p) {
        return logNorm.inverseCumulativeProbability(p);
    }

    // -------- Main method example --------

    /**
     * Demonstrates usage of the class with example values.
     *
     * @param args not used
     */
    public static void main(String[] args) {
        double[] xValues = {0.5, 1.0, 2.0, 5.0};
        double[] pValues = {0.1, 0.5, 0.9};

        LogNormalFunctions logFuncs = new LogNormalFunctions(0.0, 0.3);

        // Arrays
        System.out.println("X values: " + Arrays.toString(xValues));
        System.out.println("CDFs:     " + Arrays.toString(logFuncs.cdf(xValues)));
        System.out.println("PDFs:     " + Arrays.toString(logFuncs.pdf(xValues)));
        System.out.println("Quantiles (inverse CDF): " + Arrays.toString(logFuncs.quantile(pValues)));
        
        // Single values
        System.out.println("CDF at 1.0: " + logFuncs.cdf(1.0));
        System.out.println("PDF at 1.0: " + logFuncs.pdf(1.0));
        System.out.println("Quantile at 0.5: " + logFuncs.quantile(0.5));
    }
}
