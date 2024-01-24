package se.sunet.edusign.saml;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class EduSignAssuranceLevelsTest {

  @Test
  void testComparator() {
    final List<String> input = List.of(EduSignAssuranceLevels.REFEDS_HIGH,
        EduSignAssuranceLevels.REFEDS_LOW, EduSignAssuranceLevels.SWAMID_AL1,
        EduSignAssuranceLevels.SWAMID_AL2, EduSignAssuranceLevels.SWAMID_AL3,
        "foo", EduSignAssuranceLevels.REFEDS_MEDIUM);

    final List<String> sorted = input.stream()
        .sorted(EduSignAssuranceLevels.uriComparator)
        .toList();

    Assertions.assertEquals(List.of(EduSignAssuranceLevels.SWAMID_AL3,
        EduSignAssuranceLevels.REFEDS_HIGH, EduSignAssuranceLevels.SWAMID_AL2,
        EduSignAssuranceLevels.REFEDS_MEDIUM, EduSignAssuranceLevels.SWAMID_AL1,
        EduSignAssuranceLevels.REFEDS_LOW, "foo"),
        sorted);
  }

}
