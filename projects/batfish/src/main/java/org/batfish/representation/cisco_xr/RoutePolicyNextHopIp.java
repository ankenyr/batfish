package org.batfish.representation.cisco_xr;

import java.util.Collections;
import java.util.Optional;
import org.batfish.common.Warnings;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.routing_policy.expr.IpNextHop;
import org.batfish.datamodel.routing_policy.expr.NextHopExpr;

public class RoutePolicyNextHopIp extends RoutePolicyNextHop {

  private Ip _address;

  public RoutePolicyNextHopIp(Ip address) {
    _address = address;
  }

  public Ip getAddress() {
    return _address;
  }

  @Override
  public Optional<NextHopExpr> toNextHopExpr(CiscoXrConfiguration cc, Configuration c, Warnings w) {
    return Optional.of(new IpNextHop(Collections.singletonList(_address)));
  }
}
