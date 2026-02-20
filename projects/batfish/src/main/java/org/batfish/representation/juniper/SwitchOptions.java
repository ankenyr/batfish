package org.batfish.representation.juniper;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;
import org.batfish.datamodel.bgp.RouteDistinguisher;
import org.batfish.datamodel.bgp.community.ExtendedCommunity;

public class SwitchOptions implements Serializable {

  private String _vtepSourceInterface;
  private RouteDistinguisher _routeDistinguisher;
  private final List<ExtendedCommunity> _vrfTargetCommunities = new ArrayList<>();
  private final List<ExtendedCommunity> _vrfTargetExportCommunities = new ArrayList<>();
  private final List<ExtendedCommunity> _vrfTargetImportCommunities = new ArrayList<>();
  private boolean _vrfTargetAuto;
  private @Nullable String _vrfImport;
  private @Nullable String _vrfExport;

  public String getVtepSourceInterface() {
    return _vtepSourceInterface;
  }

  public RouteDistinguisher getRouteDistinguisher() {
    return _routeDistinguisher;
  }

  public List<ExtendedCommunity> getVrfTargetCommunities() {
    return _vrfTargetCommunities;
  }

  public List<ExtendedCommunity> getVrfTargetExportCommunities() {
    return _vrfTargetExportCommunities;
  }

  public List<ExtendedCommunity> getVrfTargetImportCommunities() {
    return _vrfTargetImportCommunities;
  }

  public boolean getVrfTargetAuto() {
    return _vrfTargetAuto;
  }

  public @Nullable String getVrfImport() {
    return _vrfImport;
  }

  public @Nullable String getVrfExport() {
    return _vrfExport;
  }

  public void setVtepSourceInterface(String vtepSourceInterface) {
    _vtepSourceInterface = vtepSourceInterface;
  }

  public void setRouteDistinguisher(RouteDistinguisher routeDistinguisher) {
    _routeDistinguisher = routeDistinguisher;
  }

  public void setVrfTargetAuto(boolean vrfTargetAuto) {
    _vrfTargetAuto = vrfTargetAuto;
  }

  public void setVrfImport(@Nullable String vrfImport) {
    _vrfImport = vrfImport;
  }

  public void setVrfExport(@Nullable String vrfExport) {
    _vrfExport = vrfExport;
  }
}
