package org.batfish.representation.aws;

import com.google.common.base.MoreObjects;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import org.batfish.common.util.CommonUtil;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.Prefix;
//import org.w3c.dom.Element;


/** Represents an AWs IPSec tunnel */
@ParametersAreNonnullByDefault
final class IpsecTunnel implements Serializable {

  private final @Nonnull String _cgwId;

  private final @Nonnull Ip _cgwInsideAddress;

  private final @Nonnull List<VpnConnection.Value> _ikeAuthProtocol;

  private final @Nonnull List<VpnConnection.Value> _ikeEncryptionProtocol;

  private final int _ikeLifetime;

  private final @Nonnull List<VpnConnection.Value> _ikePerfectForwardSecrecy;

  private final @Nonnull String _ikePreSharedKeyHash;

  private final @Nonnull List<VpnConnection.Value> _ipsecAuthProtocol;

  private final @Nonnull List<VpnConnection.Value> _ipsecEncryptionProtocol;

  private final int _ipsecLifetime;

  private final @Nonnull String _ipsecMode;

  private final @Nonnull List<VpnConnection.Value> _ipsecPerfectForwardSecrecy;

  private final @Nonnull String _ipsecProtocol;

  private final @Nullable Long _vgwBgpAsn;

  private final @Nonnull Ip _vgwInsideAddress;

  private final int _vgwInsidePrefixLength;

  private final @Nonnull Ip _vgwOutsideAddress;

  static IpsecTunnel create(VpnConnection.TunnelOptions tunnelOption, String cgwId) {

    Builder builder = new Builder();
    builder.setCgwId(cgwId);


    builder.setVgwOutsideAddress(Ip.parse(tunnelOption.getOutsideIpAddress()));

    String[] ip = tunnelOption.getInsideIpAddress().split("/");
    Prefix ip_prefix = Prefix.parse(tunnelOption.getInsideIpAddress());
    //  Ip vgwInsideIp = Ip.parse(ip[0]);

    builder.setVgwInsideAddress(ip_prefix.getFirstHostIp());
    builder.setVgwInsidePrefixLength(Integer.parseInt(ip[1]));
    builder.setCgwInsideAddress(ip_prefix.getLastHostIp());



    builder.setIkeAuthProtocol(tunnelOption.getPhase1IntegrityAlgorithm());
    builder.setIkeEncryptionProtocol(tunnelOption.getPhase2EncryptionAlgorithm());
    builder.setIkePerfectForwardSecrecy(tunnelOption.getPhase1DHGroupNumbers());
    builder.setIkePreSharedKeyHash(
        CommonUtil.sha256Digest(
            tunnelOption.getPresharedKey()
                + CommonUtil.salt()));

    // esp is the only option
    builder.setIpsecProtocol("esp");
    builder.setIpsecAuthProtocol(tunnelOption.getPhase2IntegrityAlgorithm());
    builder.setIpsecEncryptionProtocol(tunnelOption.getPhase2EncryptionAlgorithm());
    builder.setIpsecPerfectForwardSecrecy(tunnelOption.getPhase2DHGroupNumbers());
    // AWS looks to support both main and aggressive but does not give options to set these.
    // Main and Aggressive are both compatible with each other.
    // https://aws.amazon.com/blogs/networking-and-content-delivery/aws-site-to-site-vpn-choosing-the-right-options-to-optimize-performance/
    builder.setIpsecMode("tunnel");

    return builder.build();
  }

  IpsecTunnel(
      String cgwId,
      Ip cgwInsideAddress,
      List<VpnConnection.Value> ikeAuthProtocol,
      List<VpnConnection.Value> ikeEncryptionProtocol,
      int ikeLifetime,
      List<VpnConnection.Value> ikePerfectForwardSecrecy,
      String ikePreSharedKeyHash,
      List<VpnConnection.Value> ipsecAuthProtocol,
      List<VpnConnection.Value> ipsecEncryptionProtocol,
      int ipsecLifetime,
      String ipsecMode,
      List<VpnConnection.Value> ipsecPerfectForwardSecrecy,
      String ipsecProtocol,
      @Nullable Long vgwBgpAsn,
      Ip vgwInsideAddress,
      int vgwInsidePrefixLength,
      Ip vgwOutsideAddress) {
    _cgwId = cgwId;
    _cgwInsideAddress = cgwInsideAddress;

    _ikeAuthProtocol = ikeAuthProtocol;
    _ikeEncryptionProtocol = ikeEncryptionProtocol;
    _ikeLifetime = ikeLifetime;
    _ikePerfectForwardSecrecy = ikePerfectForwardSecrecy;
    _ikePreSharedKeyHash = ikePreSharedKeyHash;

    _ipsecAuthProtocol = ipsecAuthProtocol;
    _ipsecEncryptionProtocol = ipsecEncryptionProtocol;
    _ipsecLifetime = ipsecLifetime;
    _ipsecMode = ipsecMode;
    _ipsecPerfectForwardSecrecy = ipsecPerfectForwardSecrecy;
    _ipsecProtocol = ipsecProtocol;

    _vgwBgpAsn = vgwBgpAsn;
    _vgwInsidePrefixLength = vgwInsidePrefixLength;
    _vgwInsideAddress = vgwInsideAddress;
    _vgwOutsideAddress = vgwOutsideAddress;
  }
  @Nullable
  String getCgwId() {
    return _cgwId;
  }
  @Nonnull
  Ip getCgwInsideAddress() {
    return _cgwInsideAddress;
  }

  @Nonnull
  List<VpnConnection.Value> getIkeAuthProtocol() {
    return _ikeAuthProtocol;
  }

  @Nonnull
  List<VpnConnection.Value> getIkeEncryptionProtocol() {
    return _ikeEncryptionProtocol;
  }

  int getIkeLifetime() {
    return _ikeLifetime;
  }

  @Nonnull
  List<VpnConnection.Value> getIkePerfectForwardSecrecy() {
    return _ikePerfectForwardSecrecy;
  }

  @Nonnull
  String getIkePreSharedKeyHash() {
    return _ikePreSharedKeyHash;
  }

  @Nonnull
  List<VpnConnection.Value> getIpsecAuthProtocol() {
    return _ipsecAuthProtocol;
  }

  @Nonnull
  List<VpnConnection.Value> getIpsecEncryptionProtocol() {
    return _ipsecEncryptionProtocol;
  }

  int getIpsecLifetime() {
    return _ipsecLifetime;
  }

  @Nonnull
  String getIpsecMode() {
    return _ipsecMode;
  }

  @Nonnull
  List<VpnConnection.Value> getIpsecPerfectForwardSecrecy() {
    return _ipsecPerfectForwardSecrecy;
  }

  @Nonnull
  String getIpsecProtocol() {
    return _ipsecProtocol;
  }

  @Nullable
  Long getVgwBgpAsn() {
    return _vgwBgpAsn;
  }

  @Nonnull
  Ip getVgwInsideAddress() {
    return _vgwInsideAddress;
  }

  int getVgwInsidePrefixLength() {
    return _vgwInsidePrefixLength;
  }

  @Nonnull
  Ip getVgwOutsideAddress() {
    return _vgwOutsideAddress;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof IpsecTunnel)) {
      return false;
    }
    IpsecTunnel that = (IpsecTunnel) o;
    return _cgwId == that._cgwId
        && _ikeLifetime == that._ikeLifetime
        && _ipsecLifetime == that._ipsecLifetime
        && Objects.equals(_vgwBgpAsn, that._vgwBgpAsn)
        && _vgwInsidePrefixLength == that._vgwInsidePrefixLength
        && Objects.equals(_cgwInsideAddress, that._cgwInsideAddress)
        && Objects.equals(_ikeAuthProtocol, that._ikeAuthProtocol)
        && Objects.equals(_ikeEncryptionProtocol, that._ikeEncryptionProtocol)
        && Objects.equals(_ikePerfectForwardSecrecy, that._ikePerfectForwardSecrecy)
        && Objects.equals(_ikePreSharedKeyHash, that._ikePreSharedKeyHash)
        && Objects.equals(_ipsecAuthProtocol, that._ipsecAuthProtocol)
        && Objects.equals(_ipsecEncryptionProtocol, that._ipsecEncryptionProtocol)
        && Objects.equals(_ipsecMode, that._ipsecMode)
        && Objects.equals(_ipsecPerfectForwardSecrecy, that._ipsecPerfectForwardSecrecy)
        && Objects.equals(_ipsecProtocol, that._ipsecProtocol)
        && Objects.equals(_vgwInsideAddress, that._vgwInsideAddress)
        && Objects.equals(_vgwOutsideAddress, that._vgwOutsideAddress);
  }

  @Override
  public int hashCode() {
    return Objects.hash(_cgwId,
        _cgwInsideAddress,
        _ikeAuthProtocol,
        _ikeEncryptionProtocol,
        _ikeLifetime,
        _ikePerfectForwardSecrecy,
        _ikePreSharedKeyHash,
        _ipsecAuthProtocol,
        _ipsecEncryptionProtocol,
        _ipsecLifetime,
        _ipsecMode,
        _ipsecPerfectForwardSecrecy,
        _ipsecProtocol,
        _vgwBgpAsn,
        _vgwInsideAddress,
        _vgwInsidePrefixLength,
        _vgwOutsideAddress);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("_cgwId", _cgwId)
        .add("_cgwInsideAddress", _cgwInsideAddress)
        .add("_ikeAuthProtocol", _ikeAuthProtocol)
        .add("_ikeEncryptionProtocol", _ikeEncryptionProtocol)
        .add("_ikeLifetime", _ikeLifetime)
        .add("_ikePerfectForwardSecrecy", _ikePerfectForwardSecrecy)
        .add("_ikePreSharedKeyHash", _ikePreSharedKeyHash)
        .add("_ipsecAuthProtocol", _ipsecAuthProtocol)
        .add("_ipsecEncryptionProtocol", _ipsecEncryptionProtocol)
        .add("_ipsecLifetime", _ipsecLifetime)
        .add("_ipsecMode", _ipsecMode)
        .add("_ipsecPerfectForwardSecrecy", _ipsecPerfectForwardSecrecy)
        .add("_ipsecProtocol", _ipsecProtocol)
        .add("_vgwBgpAsn", _vgwBgpAsn)
        .add("_vgwInsideAddress", _vgwInsideAddress)
        .add("_vgwInsidePrefixLength", _vgwInsidePrefixLength)
        .add("_vgwOutsideAddress", _vgwOutsideAddress)
        .toString();
  }

  static final class Builder {
    private Ip _cgwInsideAddress;
    private String _cgwId;
    private List<VpnConnection.Value> _ikeAuthProtocol;
    private List<VpnConnection.Value> _ikeEncryptionProtocol;
    private int _ikeLifetime;
    private List<VpnConnection.Value> _ikePerfectForwardSecrecy;
    private String _ikePreSharedKeyHash;
    private List<VpnConnection.Value> _ipsecAuthProtocol;
    private List<VpnConnection.Value> _ipsecEncryptionProtocol;
    private int _ipsecLifetime;
    private String _ipsecMode;
    private List<VpnConnection.Value> _ipsecPerfectForwardSecrecy;
    private String _ipsecProtocol;
    private Long _vgwBgpAsn;
    private Ip _vgwInsideAddress;
    private int _vgwInsidePrefixLength;
    private Ip _vgwOutsideAddress;

    private Builder() {}

    Builder setCgwInsideAddress(Ip cgwInsideAddress) {
      _cgwInsideAddress = cgwInsideAddress;
      return this;
    }

    Builder setCgwId(String cgwId) {
      _cgwId = cgwId;
      return this;
    }

    Builder setIkeAuthProtocol(List<VpnConnection.Value> ikeAuthProtocol) {
      _ikeAuthProtocol = ikeAuthProtocol;
      return this;
    }

    Builder setIkeEncryptionProtocol(List<VpnConnection.Value> ikeEncryptionProtocol) {
      _ikeEncryptionProtocol = ikeEncryptionProtocol;
      return this;
    }

    Builder setIkeLifetime(int ikeLifetime) {
      _ikeLifetime = ikeLifetime;
      return this;
    }

    Builder setIkePerfectForwardSecrecy(List<VpnConnection.Value> ikePerfectForwardSecrecy) {
      _ikePerfectForwardSecrecy = ikePerfectForwardSecrecy;
      return this;
    }

    Builder setIkePreSharedKeyHash(String ikePreSharedKeyHash) {
      _ikePreSharedKeyHash = ikePreSharedKeyHash;
      return this;
    }

    Builder setIpsecAuthProtocol(List<VpnConnection.Value> ipsecAuthProtocol) {
      _ipsecAuthProtocol = ipsecAuthProtocol;
      return this;
    }

    Builder setIpsecEncryptionProtocol(List<VpnConnection.Value> ipsecEncryptionProtocol) {
      _ipsecEncryptionProtocol = ipsecEncryptionProtocol;
      return this;
    }

    Builder setIpsecLifetime(int ipsecLifetime) {
      _ipsecLifetime = ipsecLifetime;
      return this;
    }

    Builder setIpsecMode(String ipsecMode) {
      _ipsecMode = ipsecMode;
      return this;
    }

    Builder setIpsecPerfectForwardSecrecy(List<VpnConnection.Value> ipsecPerfectForwardSecrecy) {
      _ipsecPerfectForwardSecrecy = ipsecPerfectForwardSecrecy;
      return this;
    }

    Builder setIpsecProtocol(String ipsecProtocol) {
      _ipsecProtocol = ipsecProtocol;
      return this;
    }

    Builder setVgwBgpAsn(@Nullable Long vgwBgpAsn) {
      _vgwBgpAsn = vgwBgpAsn;
      return this;
    }

    Builder setVgwInsideAddress(Ip vgwInsideAddress) {
      _vgwInsideAddress = vgwInsideAddress;
      return this;
    }

    Builder setVgwInsidePrefixLength(int vgwInsidePrefixLength) {
      _vgwInsidePrefixLength = vgwInsidePrefixLength;
      return this;
    }

    Builder setVgwOutsideAddress(Ip vgwOutsideAddress) {
      _vgwOutsideAddress = vgwOutsideAddress;
      return this;
    }

    IpsecTunnel build() {
      return new IpsecTunnel(
          _cgwId,
          _cgwInsideAddress,
          _ikeAuthProtocol,
          _ikeEncryptionProtocol,
          _ikeLifetime,
          _ikePerfectForwardSecrecy,
          _ikePreSharedKeyHash,
          _ipsecAuthProtocol,
          _ipsecEncryptionProtocol,
          _ipsecLifetime,
          _ipsecMode,
          _ipsecPerfectForwardSecrecy,
          _ipsecProtocol,
          _vgwBgpAsn,
          _vgwInsideAddress,
          _vgwInsidePrefixLength,
          _vgwOutsideAddress);
    }
  }
}
