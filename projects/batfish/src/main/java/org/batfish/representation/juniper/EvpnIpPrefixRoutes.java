package org.batfish.representation.juniper;

import java.io.Serializable;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

/** Configuration for EVPN ip-prefix-routes under a routing instance. */
@ParametersAreNonnullByDefault
public final class EvpnIpPrefixRoutes implements Serializable {

  public enum AdvertiseMode {
    DIRECT_NEXTHOP,
    GATEWAY_ADDRESS
  }

  private @Nullable AdvertiseMode _advertise;
  private @Nullable EvpnEncapsulation _encapsulation;
  private @Nullable Integer _vni;
  private @Nullable String _importPolicy;
  private @Nullable String _exportPolicy;

  public @Nullable AdvertiseMode getAdvertise() {
    return _advertise;
  }

  public @Nullable EvpnEncapsulation getEncapsulation() {
    return _encapsulation;
  }

  public @Nullable Integer getVni() {
    return _vni;
  }

  public @Nullable String getImportPolicy() {
    return _importPolicy;
  }

  public @Nullable String getExportPolicy() {
    return _exportPolicy;
  }

  public void setAdvertise(AdvertiseMode advertise) {
    _advertise = advertise;
  }

  public void setEncapsulation(EvpnEncapsulation encapsulation) {
    _encapsulation = encapsulation;
  }

  public void setVni(int vni) {
    _vni = vni;
  }

  public void setImportPolicy(String importPolicy) {
    _importPolicy = importPolicy;
  }

  public void setExportPolicy(String exportPolicy) {
    _exportPolicy = exportPolicy;
  }
}
