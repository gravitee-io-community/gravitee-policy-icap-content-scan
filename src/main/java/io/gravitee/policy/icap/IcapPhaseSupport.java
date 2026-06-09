package io.gravitee.policy.icap;

import io.gravitee.resource.icap.IcapResource;
import io.gravitee.resource.icap.model.IcapOptions;
import io.gravitee.resource.icap.model.IcapPhase;
import java.util.Set;

final class IcapPhaseSupport {

  private IcapPhaseSupport() {}

  static String requiredIcapMethod(IcapPhase phase) {
    return phase == IcapPhase.REQUEST ? "REQMOD" : "RESPMOD";
  }

  static boolean isScanSupported(IcapResource resource, IcapPhase phase) {
    if (resource == null || phase == null) {
      return false;
    }
    IcapOptions options = resource.getOptions();
    if (options == null) {
      return true;
    }
    Set<String> methods = options.getMethods();
    if (methods == null || methods.isEmpty()) {
      return true;
    }
    return methods.contains(requiredIcapMethod(phase));
  }
}
