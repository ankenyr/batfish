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
import org.w3c.dom.Element;

/** Represents an AWs IPSec tunnel */
@ParametersAreNonnullByDefault
final class IpsecTunnel implements Serializable {

  private @Nullable Long _cgwBgpAsn;

  private final @Nonnull Ip _cgwInsideAddress;

  private final int _cgwInsidePrefixLength;

  private final @Nonnull Ip _cgwOutsideAddress;

  private final @Nonnull List<VpnConnection.Value> _ikeAuthProtocol;

  private final @Nonnull List<VpnConnection.Value> _ikeEncryptionProtocol;

  private final int _ikeLifetime;

  private final @Nonnull String _ikeMode;

  private final @Nonnull List<VpnConnection.Value> _ikePerfectForwardSecrecy;

  private final @Nonnull String _ikePreSharedKeyHash;

  private final @Nonnull List<VpnConnection.Value> _ipsecAuthProtocol;

  private final @Nonnull List<VpnConnection.Value> _ipsecEncryptionProtocol;

  private final int _ipsecLifetime;

  private final @Nonnull String _ipsecMode;

  private final @Nonnull List<VpnConnection.Value> _ipsecPerfectForwardSecrecy;

  private final @Nonnull String _ipsecProtocol;

  private @Nullable Long _vgwBgpAsn;

  private final @Nonnull Ip _vgwInsideAddress;

  private final int _vgwInsidePrefixLength;

  private final @Nonnull Ip _vgwOutsideAddress;

  static IpsecTunnel create(Element ipsecTunnel, boolean isBgpConnection, VpnConnection.TunnelOptions tunnelOption, String customerGatewayId) {

    Builder builder = new Builder();

    Element cgwElement = (Element) ipsecTunnel.getElementsByTagName(AwsVpcEntity.XML_KEY_CUSTOMER_GATEWAY).item(0);

    // The next two will be set by CGW after everything is parsed
    // This will be set later
    builder.setcgwOutsideAddress(Ip.parse(Utils.textOfFirstXmlElementWithInnerTag(cgwElement,AwsVpcEntity.XML_KEY_TUNNEL_OUTSIDE_ADDRESS,AwsVpcEntity.XML_KEY_IP_ADDRESS)));

    // we see asn configured only for BGP connections
//    if (isBgpConnection) {
//      builder.setCgwBgpAsn(
//          Long.parseLong(
//              Utils.textOfFirstXmlElementWithInnerTag(
//                  cgwElement, AwsVpcEntity.XML_KEY_BGP, AwsVpcEntity.XML_KEY_ASN)));
//    }

    builder.setVgwOutsideAddress(tunnelOption.getOutsideIpAddress());

    Prefix prefix = Prefix.parse(tunnelOption.getTunnelInsideCidr());
    builder.setVgwInsideAddress(prefix.getFirstHostIp());

    builder.setVgwInsidePrefixLength(prefix.getPrefixLength());
    builder.setcgwInsideAddress(prefix.getLastHostIp());
    builder.setCgwInsidePrefixLength(prefix.getPrefixLength());

    // Needs to be set by TGW
    // we see asn configured only for BGP connections
//    if (isBgpConnection) {
//      builder.setVgwBgpAsn(
//          Long.parseLong(
//              Utils.textOfFirstXmlElementWithInnerTag(
//                  vgwElement, AwsVpcEntity.XML_KEY_BGP, AwsVpcEntity.XML_KEY_ASN)));
//    }
//    Element ikeElement =
//        (Element) ipsecTunnel.getElementsByTagName(AwsVpcEntity.XML_KEY_IKE).item(0);

    builder.setIkeAuthProtocol(tunnelOption.getPhase1IntegrityAlgorithm());
    builder.setIkeEncryptionProtocol(tunnelOption.getPhase2EncryptionAlgorithm());
    builder.setIkeLifetime(tunnelOption.getReplayWindowSize());

    builder.setIkePerfectForwardSecrecy(tunnelOption.getPhase1DHGroupNumbers());
    // ike mode is always main.
    builder.setIkeMode("main");
    builder.setIkePreSharedKeyHash(
        CommonUtil.sha256Digest(
            tunnelOption.getPresharedKey()
                + CommonUtil.salt()));
    // IPSec protocol is always esp.
    builder.setIpsecProtocol("esp");
    builder.setIpsecAuthProtocol(tunnelOption.getPhase2IntegrityAlgorithm());
    builder.setIpsecEncryptionProtocol(tunnelOption.getPhase2EncryptionAlgorithm());
    builder.setIpsecLifetime(tunnelOption.getPhase2LifetimeSeconds());
    builder.setIpsecPerfectForwardSecrecy(tunnelOption.getPhase2DHGroupNumbers());
    // IPSec mode is always tunnel.
    builder.setIpsecMode("tunnel");

    return builder.build();
  }

  IpsecTunnel(
      @Nullable Long cgwBgpAsn,
      Ip cgwInsideAddress,
      int cgwInsidePrefixLength,
      Ip cgwOutsideAddress,
      List<VpnConnection.Value> ikeAuthProtocol,
      List<VpnConnection.Value> ikeEncryptionProtocol,
      int ikeLifetime,
      String ikeMode,
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
    _cgwBgpAsn = cgwBgpAsn;
    _cgwInsideAddress = cgwInsideAddress;
    _cgwInsidePrefixLength = cgwInsidePrefixLength;
    _cgwOutsideAddress = cgwOutsideAddress;

    _ikeAuthProtocol = ikeAuthProtocol;
    _ikeEncryptionProtocol = ikeEncryptionProtocol;
    _ikeLifetime = ikeLifetime;
    _ikeMode = ikeMode;
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
  Long getCgwBgpAsn() {
    return _cgwBgpAsn;
  }


  void setCgwBgpAsn(@Nullable Long cgwBgpAsn) {
    _cgwBgpAsn = cgwBgpAsn;
  };

  @Nonnull
  Ip getCgwInsideAddress() {
    return _cgwInsideAddress;
  }

  int getCgwInsidePrefixLength() {
    return _cgwInsidePrefixLength;
  }

  @Nonnull
  Ip getCgwOutsideAddress() {
    return _cgwOutsideAddress;
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
  String getIkeMode() {
    return _ikeMode;
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

  void setVgwBgpAsn(@Nullable Long vgwBgpAsn) {
    _vgwBgpAsn = vgwBgpAsn;
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
    return Objects.equals(_cgwBgpAsn, that._cgwBgpAsn)
        && _cgwInsidePrefixLength == that._cgwInsidePrefixLength
        && _ikeLifetime == that._ikeLifetime
        && _ipsecLifetime == that._ipsecLifetime
        && Objects.equals(_vgwBgpAsn, that._vgwBgpAsn)
        && _vgwInsidePrefixLength == that._vgwInsidePrefixLength
        && Objects.equals(_cgwInsideAddress, that._cgwInsideAddress)
        && Objects.equals(_cgwOutsideAddress, that._cgwOutsideAddress)
        && Objects.equals(_ikeAuthProtocol, that._ikeAuthProtocol)
        && Objects.equals(_ikeEncryptionProtocol, that._ikeEncryptionProtocol)
        && Objects.equals(_ikeMode, that._ikeMode)
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
    return Objects.hash(
        _cgwBgpAsn,
        _cgwInsideAddress,
        _cgwInsidePrefixLength,
        _cgwOutsideAddress,
        _ikeAuthProtocol,
        _ikeEncryptionProtocol,
        _ikeLifetime,
        _ikeMode,
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
        .add("_cgwBgpAsn", _cgwBgpAsn)
        .add("_cgwInsideAddress", _cgwInsideAddress)
        .add("_cgwInsidePrefixLength", _cgwInsidePrefixLength)
        .add("_cgwOutsideAddress", _cgwOutsideAddress)
        .add("_ikeAuthProtocol", _ikeAuthProtocol)
        .add("_ikeEncryptionProtocol", _ikeEncryptionProtocol)
        .add("_ikeLifetime", _ikeLifetime)
        .add("_ikeMode", _ikeMode)
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
    private Long _cgwBgpAsn;
    private Ip _cgwInsideAddress;
    private int _cgwInsidePrefixLength;
    private Ip _cgwOutsideAddress;
    private List<VpnConnection.Value> _ikeAuthProtocol;
    private List<VpnConnection.Value> _ikeEncryptionProtocol;
    private int _ikeLifetime;
    private String _ikeMode;
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

    Builder setCgwBgpAsn(@Nullable Long cgwBgpAsn) {
      _cgwBgpAsn = cgwBgpAsn;
      return this;
    }

    Builder setcgwInsideAddress(Ip cgwInsideAddress) {
      _cgwInsideAddress = cgwInsideAddress;
      return this;
    }

    Builder setCgwInsidePrefixLength(int cgwInsidePrefixLength) {
      _cgwInsidePrefixLength = cgwInsidePrefixLength;
      return this;
    }

    Builder setcgwOutsideAddress(Ip cgwOutsideAddress) {
      _cgwOutsideAddress = cgwOutsideAddress;
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

    Builder setIkeMode(String ikeMode) {
      _ikeMode = ikeMode;
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
          _cgwBgpAsn,
          _cgwInsideAddress,
          _cgwInsidePrefixLength,
          _cgwOutsideAddress,
          _ikeAuthProtocol,
          _ikeEncryptionProtocol,
          _ikeLifetime,
          _ikeMode,
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
