package se.sunet.edusign.saml;

import java.util.Comparator;

/**
 * Constants for assurance level URI:s within SWAMID.
 *
 * @author Martin Lindström
 */
public class EduSignAssuranceLevels {

  /** SWAMID AL1 */
  public final static String SWAMID_AL1 = "http://www.swamid.se/policy/assurance/al1";

  /** Custom URI for SWAMID AL1 with MFA. */
  public final static String CUSTOM_SWAMID_AL1_MFA = "http://www.swamid.se/policy/assurance/al1/refeds-mfa";

  /** SWAMID AL2 */
  public final static String SWAMID_AL2 = "http://www.swamid.se/policy/assurance/al2";

  /** Custom URI for SWAMID AL2 with MFA. */
  public final static String CUSTOM_SWAMID_AL2_MFA = "http://www.swamid.se/policy/assurance/al2/refeds-mfa";

  /** SWAMID AL3 */
  public final static String SWAMID_AL3 = "http://www.swamid.se/policy/assurance/al3";

  /** REFEDS Low */
  public final static String REFEDS_LOW = "https://refeds.org/assurance/IAP/low";

  /** Custom URI for REFEDS Low with MFA. */
  public final static String CUSTOM_REFEDS_LOW_MFA = "https://refeds.org/assurance/IAP/low/refeds-mfa";

  /** REFEDS Medium */
  public final static String REFEDS_MEDIUM = "https://refeds.org/assurance/IAP/medium";

  /** Custom URI for REFEDS Medium with MFA. */
  public final static String CUSTOM_REFEDS_MEDIUM_MFA = "https://refeds.org/assurance/IAP/medium/refeds-mfa";

  /** REFEDS High */
  public final static String REFEDS_HIGH = "https://refeds.org/assurance/IAP/high";

  /** Custom URI for REFEDS High with MFA. */
  public final static String CUSTOM_REFEDS_HIGH_MFA = "https://refeds.org/assurance/IAP/high/refeds-mfa";

  /**
   * Comparator for comparing assurance level URI:s.
   */
  public static Comparator<String> uriComparator = (u1, u2) -> {
    return Integer.compare(getComparatorOrder(u1), getComparatorOrder(u2));
  };

  /**
   * Gets the comparator order for URI:s. The lower comparator order the higher valued URI.
   *
   * @param uri the assurance level URI
   * @return an integer
   */
  public static int getComparatorOrder(final String uri) {
    return switch (uri) {
    case SWAMID_AL3 -> 0;
    case REFEDS_HIGH -> 1;
    case SWAMID_AL2 -> 2;
    case REFEDS_MEDIUM -> 3;
    case SWAMID_AL1 -> 4;
    case REFEDS_LOW -> 5;
    default -> Integer.MAX_VALUE;
    };
  }

  private EduSignAssuranceLevels() {
  }

}
