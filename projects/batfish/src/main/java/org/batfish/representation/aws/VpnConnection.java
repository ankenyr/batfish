package org.batfish.representation.aws;

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkArgument;
import static org.batfish.representation.aws.AwsConfiguration.vpnExternalInterfaceName;
import static org.batfish.representation.aws.AwsConfiguration.vpnInterfaceName;
import static org.batfish.representation.aws.AwsConfiguration.vpnTunnelId;
import static org.batfish.representation.aws.Utils.addStaticRoute;
import static org.batfish.representation.aws.Utils.createBackboneConnection;
import static org.batfish.representation.aws.Utils.toStaticRoute;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.collect.ImmutableSortedSet;
import java.io.IOException;
import java.io.Serializable;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.batfish.common.BatfishException;
import org.batfish.common.Warnings;
import org.batfish.datamodel.BgpActivePeerConfig;
import org.batfish.datamodel.ConcreteInterfaceAddress;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.DiffieHellmanGroup;
import org.batfish.datamodel.EncryptionAlgorithm;
import org.batfish.datamodel.IkeAuthenticationMethod;
import org.batfish.datamodel.IkeHashingAlgorithm;
import org.batfish.datamodel.IkeKeyType;
import org.batfish.datamodel.IkePhase1Key;
import org.batfish.datamodel.IkePhase1Policy;
import org.batfish.datamodel.IkePhase1Proposal;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.IpsecAuthenticationAlgorithm;
import org.batfish.datamodel.IpsecEncapsulationMode;
import org.batfish.datamodel.IpsecPeerConfig;
import org.batfish.datamodel.IpsecPhase2Policy;
import org.batfish.datamodel.IpsecPhase2Proposal;
import org.batfish.datamodel.IpsecProtocol;
import org.batfish.datamodel.IpsecStaticPeerConfig;
import org.batfish.datamodel.LongSpace;
import org.batfish.datamodel.OriginType;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.RoutingProtocol;
import org.batfish.datamodel.Vrf;
import org.batfish.datamodel.bgp.Ipv4UnicastAddressFamily;
import org.batfish.datamodel.routing_policy.RoutingPolicy;
import org.batfish.datamodel.routing_policy.expr.LiteralOrigin;
import org.batfish.datamodel.routing_policy.expr.MatchProtocol;
import org.batfish.datamodel.routing_policy.statement.If;
import org.batfish.datamodel.routing_policy.statement.SetOrigin;
import org.batfish.datamodel.routing_policy.statement.Statement;
import org.batfish.datamodel.routing_policy.statement.Statements;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/** Represents an AWS VPN connection */
@JsonIgnoreProperties(ignoreUnknown = true)
@ParametersAreNonnullByDefault
final class VpnConnection implements AwsVpcEntity, Serializable {

  // the VRF for interfaces that underlie the IPSec tunnel. they are the ones with public IP.
  static final String VPN_UNDERLAY_VRF_NAME = "vrf-vpn-underlay";

  /** Export policy to backbone */
  static final String VPN_TO_BACKBONE_EXPORT_POLICY_NAME = "~vpn~to~backbone~export~policy~";

  /**
   * Routing policy statement that exports connected routes. It is used to advertize underlay
   * interface addresses (public IPs) to the backbone.
   */
  static Statement EXPORT_CONNECTED_STATEMENT =
      new If(
          new MatchProtocol(RoutingProtocol.CONNECTED),
          ImmutableList.of(
              new SetOrigin(new LiteralOrigin(OriginType.INCOMPLETE, null)),
              Statements.ExitAccept.toStaticStatement()));

  private static DiffieHellmanGroup toDiffieHellmanGroup(String perfectForwardSecrecy) {
    switch (perfectForwardSecrecy) {
      case "2":
        return DiffieHellmanGroup.GROUP2;
      case "5":
        return DiffieHellmanGroup.GROUP5;
      case "14":
        return DiffieHellmanGroup.GROUP14;
      case "15":
        return DiffieHellmanGroup.GROUP15;
      case "16":
        return DiffieHellmanGroup.GROUP16;
      case "17":
        return DiffieHellmanGroup.GROUP17;
      case "18":
        return DiffieHellmanGroup.GROUP18;
      case "19":
        return DiffieHellmanGroup.GROUP19;
      case "20":
        return DiffieHellmanGroup.GROUP20;
      case "21":
        return DiffieHellmanGroup.GROUP21;
      case "22":
        return DiffieHellmanGroup.GROUP22;
      case "23":
        return DiffieHellmanGroup.GROUP23;
      case "24":
        return DiffieHellmanGroup.GROUP24;
      default:
        throw new BatfishException(
            "No conversion to Diffie-Hellman group for string: \"" + perfectForwardSecrecy + "\"");
    }
  }

  private static EncryptionAlgorithm toEncryptionAlgorithm(String encryptionProtocol) {
    switch (encryptionProtocol) {
      case "aes-128-cbc":
      case "AES128":
        return EncryptionAlgorithm.AES_128_CBC;
      case "AES256":
        return EncryptionAlgorithm.AES_256_CBC;
      case "AES128-GCM-16":
        return EncryptionAlgorithm.AES_128_GCM;
      case "AES256-GCM-16":
        return EncryptionAlgorithm.AES_256_GCM;
      default:
        throw new BatfishException(
            "No conversion to encryption algorithm for string: \"" + encryptionProtocol + "\"");
    }
  }

  private static IkeHashingAlgorithm toIkeAuthenticationAlgorithm(String ikeAuthProtocol) {
    switch (ikeAuthProtocol) {
      case "sha1":
      case "SHA1":
        return IkeHashingAlgorithm.SHA1;
      case "SHA2-256":
        return IkeHashingAlgorithm.SHA_256;
      case "SHA2-384":
        return IkeHashingAlgorithm.SHA_384;
      case "SHA2-512":
        return IkeHashingAlgorithm.SHA_512;
      default:
        throw new BatfishException(
            "No conversion to ike authentication algorithm for string: \""
                + ikeAuthProtocol
                + "\"");
    }
  }

  private static IpsecAuthenticationAlgorithm toIpsecAuthenticationAlgorithm(
      String ipsecAuthProtocol) {
    switch (ipsecAuthProtocol) {
      case "hmac-sha1-96":
      case "SHA1":
        return IpsecAuthenticationAlgorithm.HMAC_SHA1_96;
      case "SHA2-256":
        return IpsecAuthenticationAlgorithm.HMAC_SHA_256_128;
      case "SHA2-384":
        return IpsecAuthenticationAlgorithm.HMAC_SHA_384;
      case "SHA2-512":
        return IpsecAuthenticationAlgorithm.HMAC_SHA_512;
      default:
        throw new BatfishException(
            "No conversion to ipsec authentication algorithm for string: \""
                + ipsecAuthProtocol
                + "\"");
    }
  }

  private static IpsecProtocol toIpsecProtocol(String ipsecProtocol) {
    switch (ipsecProtocol) {
      case "esp":
        return IpsecProtocol.ESP;
      default:
        throw new BatfishException(
            "No conversion to ipsec protocol for string: \"" + ipsecProtocol + "\"");
    }
  }

  private static @Nullable IpsecEncapsulationMode toIpsecEncapdulationMode(
      String ipsecEncapsulationMode, Warnings warnings) {
    switch (ipsecEncapsulationMode) {
      case "tunnel":
        return IpsecEncapsulationMode.TUNNEL;
      case "transport":
        return IpsecEncapsulationMode.TRANSPORT;
      default:
        warnings.redFlagf("No IPsec encapsulation mode for string '%s'", ipsecEncapsulationMode);
        return null;
    }
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  @ParametersAreNonnullByDefault
  private static class VpnRoute {

    @JsonCreator
    private static VpnRoute create(
        @JsonProperty(JSON_KEY_DESTINATION_CIDR_BLOCK) @Nullable Prefix destinationCidrBlock) {
      checkArgument(
          destinationCidrBlock != null, "Destination CIDR block cannot be null in VpnRoute");
      return new VpnRoute(destinationCidrBlock);
    }

    private final @Nonnull Prefix _destinationCidrBlock;

    private VpnRoute(Prefix destinationCidrBlock) {
      _destinationCidrBlock = destinationCidrBlock;
    }

    @Nonnull
    Prefix getDestinationCidrBlock() {
      return _destinationCidrBlock;
    }
  }
  public static class Value implements Serializable {
    private final String _value;

    @JsonCreator
    public Value(@JsonProperty("Value") @Nullable String value) {
      _value = value != null ? value : "";
    }

    String getValue() {
      return _value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof Value)) {
        return false;
      }
      Value that = (Value) o;
      return this._value.equals(that._value);
    };
    @Override
    public int hashCode() {
      return Objects.hash(
              _value);
    }

  }
  @JsonIgnoreProperties(ignoreUnknown = true)
  @ParametersAreNonnullByDefault
  public static class TunnelOptions implements Serializable {
    private final List<Value> _ikeVersions;
    private final List<Value> _phase1EncryptionAlgorithm;
    private final List<Value> _phase1IntegrityAlgorithm;
    private final List<Value> _phase1DHGroupNumbers;
    private final List<Value> _phase2EncryptionAlgorithm;
    private final List<Value> _phase2IntegrityAlgorithms;
    private final List<Value> _phase2DHGroupNumbers;

    @JsonCreator
    private static TunnelOptions create(
            @JsonProperty(JSON_KEY_IKE_VERSIONS) @Nullable List<Value> ikeVersions,
            @JsonProperty(JSON_KEY_PHASE1_ENCRYPTION_ALGORITHMS) @Nullable List<Value> phase1EncryptionAlgorithm,
            @JsonProperty(JSON_KEY_PHASE1_INTEGRITY_ALGORITHMS) @Nullable List<Value> phase1IntegrityAlgorithm,
            @JsonProperty(JSON_KEY_PHASE1_DH_GROUP_NUMBERS) @Nullable List<Value> phase1DHGroupNumbers,
            @JsonProperty(JSON_KEY_PHASE2_ENCRYPTION_ALGORITHMS) @Nullable List<Value> phase2EncryptionAlgorithm,
            @JsonProperty(JSON_KEY_PHASE2_INTEGRITY_ALGORITHMS) @Nullable List<Value> phase2IntegrityAlgorithms,
            @JsonProperty(JSON_KEY_PHASE2_DH_GROUP_NUMBERS) @Nullable List<Value> phase2DHGroupNumbers
    ) {
      return new TunnelOptions(
              ikeVersions,
              firstNonNull(phase1EncryptionAlgorithm, List.of(
                      new Value("AES128"),
                      new Value("AES256"),
                      new Value("AES128-GCM-16"),
                      new Value("AES256-GCM-16")
              )),
              firstNonNull(phase1IntegrityAlgorithm, List.of(
                      new Value("SHA1"),
                      new Value("SHA2-256"),
                      new Value("SHA2-384"),
                      new Value("SHA2-512")
              )),
              firstNonNull(phase1DHGroupNumbers, List.of(
                      new Value("2"),
                      new Value("14"),
                      new Value("15"),
                      new Value("16"),
                      new Value("17"),
                      new Value("18"),
                      new Value("19"),
                      new Value("20"),
                      new Value("21"),
                      new Value("22"),
                      new Value("23"),
                      new Value("24")
              )),
              firstNonNull(phase2EncryptionAlgorithm, List.of(
                      new Value("AES128"),
                      new Value("AES256"),
                      new Value("AES128-GCM-16"),
                      new Value("AES256-GCM-16")
              )),
              firstNonNull(phase2IntegrityAlgorithms, List.of(
                      new Value("SHA1"),
                      new Value("SHA2-256"),
                      new Value("SHA2-384"),
                      new Value("SHA2-512")
              )),
              firstNonNull(phase2DHGroupNumbers, List.of(
                      new Value("2"),
                      new Value("5"),
                      new Value("14"),
                      new Value("15"),
                      new Value("16"),
                      new Value("17"),
                      new Value("18"),
                      new Value("19"),
                      new Value("20"),
                      new Value("21"),
                      new Value("22"),
                      new Value("23"),
                      new Value("24")
              ))
      );
    }

    private TunnelOptions(
            @Nullable List<Value> ikeVersions,
            @Nullable List<Value> phase1EncryptionAlgorithm,
            @Nullable List<Value> phase1IntegrityAlgorithm,
            @Nullable List<Value> phase1DHGroupNumbers,
            @Nullable List<Value> phase2EncryptionAlgorithm,
            @Nullable List<Value> phase2IntegrityAlgorithms,
            @Nullable List<Value> phase2DHGroupNumbers
    ) {
      _ikeVersions = ikeVersions;
      _phase1EncryptionAlgorithm = phase1EncryptionAlgorithm;
      _phase1IntegrityAlgorithm = phase1IntegrityAlgorithm;
      _phase1DHGroupNumbers = phase1DHGroupNumbers;
      _phase2EncryptionAlgorithm = phase2EncryptionAlgorithm;
      _phase2IntegrityAlgorithms = phase2IntegrityAlgorithms;
      _phase2DHGroupNumbers = phase2DHGroupNumbers;
    }

    List<Value> getIkeVersion() { return _ikeVersions; }
    List<Value> getPhase1EncryptionAlgorithm() { return _phase1EncryptionAlgorithm; }
    List<Value> getPhase1IntegrityAlgorithm() { return _phase1IntegrityAlgorithm; }
    List<Value> getPhase1DHGroupNumbers() { return _phase1DHGroupNumbers; }
    List<Value> getPhase2EncryptionAlgorithm() { return _phase2EncryptionAlgorithm; }
    List<Value> getPhase2IntegrityAlgorithm() { return _phase2IntegrityAlgorithms; }
    List<Value> getPhase2DHGroupNumbers() { return _phase2DHGroupNumbers; }
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  @ParametersAreNonnullByDefault
  private static class Options implements Serializable {

    @JsonCreator
    private static Options create(
        @JsonProperty(JSON_KEY_TUNNEL_OPTIONS) @Nullable List<TunnelOptions> tunnelOptions,
        @JsonProperty(JSON_KEY_STATIC_ROUTES_ONLY) @Nullable Boolean staticRoutesOnly) {
      return new Options(firstNonNull(tunnelOptions, Collections.emptyList()), firstNonNull(staticRoutesOnly, false));
    }

    private final boolean _staticRoutesOnly;
    private final List<TunnelOptions> _tunnelOptions;

    private Options(List<TunnelOptions> tunnelOptions, boolean staticRoutesOnly) {
      _tunnelOptions = tunnelOptions;
      _staticRoutesOnly = staticRoutesOnly;
    }

    TunnelOptions getTunnelOptionAtIndex(int index) {
      if (index < 0 || index >= _tunnelOptions.size()) {
        throw new IndexOutOfBoundsException("Index " + index + " is out of bounds for length " + _tunnelOptions.size());
      }
      return _tunnelOptions.get(index);
    }

    boolean getStaticRoutesOnly() {
      return _staticRoutesOnly;
    }
    List<TunnelOptions> getTunnelOptions() {
      return _tunnelOptions;
    }
  }

  enum GatewayType {
    TRANSIT,
    VPN
  }

  private final @Nonnull String _customerGatewayId;

  private final @Nonnull List<IpsecTunnel> _ipsecTunnels;

  private final boolean _isBgpConnection;

  private final @Nonnull List<Prefix> _routes;

  private final boolean _staticRoutesOnly;

  private final @Nonnull List<VgwTelemetry> _vgwTelemetrys;

  private final @Nonnull String _vpnConnectionId;

  private final @Nonnull GatewayType _awsGatewayType;

  private final @Nonnull String _awsGatewayId;

  @JsonCreator
  private static VpnConnection create(
      @JsonProperty(JSON_KEY_VPN_CONNECTION_ID) @Nullable String vpnConnectionId,
      @JsonProperty(JSON_KEY_CUSTOMER_GATEWAY_ID) @Nullable String customerGatewayId,
      @JsonProperty(JSON_KEY_TRANSIT_GATEWAY_ID) @Nullable String transitGatewayId,
      @JsonProperty(JSON_KEY_VPN_GATEWAY_ID) @Nullable String vpnGatewayId,
      @JsonProperty(JSON_KEY_CUSTOMER_GATEWAY_CONFIGURATION) @Nullable String cgwConfiguration,
      @JsonProperty(JSON_KEY_ROUTES) @Nullable List<VpnRoute> routes,
      @JsonProperty(JSON_KEY_VGW_TELEMETRY) @Nullable List<VgwTelemetry> vgwTelemetrys,
      @JsonProperty(JSON_KEY_OPTIONS) @Nullable Options options) {
    checkArgument(vpnConnectionId != null, "VPN connection Id cannot be null");
    checkArgument(
        customerGatewayId != null, "Customer gateway Id cannot be null for VPN connection");
    checkArgument(
        transitGatewayId != null || vpnGatewayId != null,
        "At least one of Transit or VPN gateway must be non-null for VPN connection");
    checkArgument(
        transitGatewayId == null || vpnGatewayId == null,
        "At least one of Transit or VPN gateway must be null for VPN connection");
    checkArgument(
        cgwConfiguration != null,
        "Customer gateway configuration cannot be null for VPN connection");
    checkArgument(routes != null, "Route list cannot be null for VPN connection");
    checkArgument(vgwTelemetrys != null, "VGW telemetry cannot be null for VPN connection");
    checkArgument(options != null, "Options cannot be null for VPN connection");

    Document document;
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      // safe parser configuration -- disallows doctypes
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      InputSource is = new InputSource(new StringReader(cgwConfiguration));
      document = builder.parse(is);
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new IllegalArgumentException(
          "Could not parse XML for CustomerGatewayConfiguration for vpn connection "
              + vpnConnectionId
              + " "
              + e);
    }

    ImmutableList.Builder<IpsecTunnel> ipsecTunnels = new ImmutableList.Builder<>();

    Element vpnConnection = (Element) document.getElementsByTagName(XML_KEY_VPN_CONNECTION).item(0);

    // the field is absent for BGP connections and is "NoBGPVPNConnection" for static connections
    boolean isBgpConnection =
        vpnConnection
                    .getElementsByTagName(AwsVpcEntity.XML_KEY_VPN_CONNECTION_ATTRIBUTES)
                    .getLength()
                == 0
            || !Utils.textOfFirstXmlElementWithTag(
                    vpnConnection, AwsVpcEntity.XML_KEY_VPN_CONNECTION_ATTRIBUTES)
                .contains("NoBGP");

    NodeList nodeList = document.getElementsByTagName(XML_KEY_IPSEC_TUNNEL);

    for (int index = 0; index < nodeList.getLength(); index++) {
      Element ipsecTunnel = (Element) nodeList.item(index);
      IpsecTunnel ipt = IpsecTunnel.create(ipsecTunnel, isBgpConnection, options.getTunnelOptionAtIndex(index));
      ipsecTunnels.add(ipt);
    }

    return new VpnConnection(
        isBgpConnection,
        vpnConnectionId,
        customerGatewayId,
        transitGatewayId != null ? GatewayType.TRANSIT : GatewayType.VPN,
        transitGatewayId != null ? transitGatewayId : vpnGatewayId,
        ipsecTunnels.build(),
        routes.stream()
            .map(VpnRoute::getDestinationCidrBlock)
            .collect(ImmutableList.toImmutableList()),
        vgwTelemetrys,
        options.getStaticRoutesOnly());
  }

  VpnConnection(
      boolean isBgpConnection,
      String vpnConnectionId,
      String customerGatewayId,
      GatewayType awsGatewayType,
      String awsGatewayId,
      List<IpsecTunnel> ipsecTunnels,
      List<Prefix> routes,
      List<VgwTelemetry> vgwTelemetrys,
      boolean staticRoutesOnly) {
    _isBgpConnection = isBgpConnection;
    _vpnConnectionId = vpnConnectionId;
    _customerGatewayId = customerGatewayId;
    _awsGatewayType = awsGatewayType;
    _awsGatewayId = awsGatewayId;
    _ipsecTunnels = ipsecTunnels;
    _routes = routes;
    _vgwTelemetrys = vgwTelemetrys;
    _staticRoutesOnly = staticRoutesOnly;
  }

  private static @Nonnull List<IkePhase1Proposal> toIkePhase1Proposal(
      String proposalName, IpsecTunnel ipsecTunnel) {

    List<IkePhase1Proposal> ikePhase1Proposals = new ArrayList<>();
    for (VpnConnection.Value dhgroup : ipsecTunnel.getIkePerfectForwardSecrecy()) {
      for (VpnConnection.Value hashing_algorithm : ipsecTunnel.getIpsecAuthProtocol()) {
        for (VpnConnection.Value encryption_algorithm : ipsecTunnel.getIkeEncryptionProtocol()) {
          IkePhase1Proposal ikePhase1Proposal = new IkePhase1Proposal(proposalName+"-"+dhgroup.getValue()+'-'+encryption_algorithm.getValue()+'-'+hashing_algorithm.getValue());
          if (ipsecTunnel.getIkePreSharedKeyHash() != null) {
            ikePhase1Proposal.setAuthenticationMethod(IkeAuthenticationMethod.PRE_SHARED_KEYS);
          }
          ikePhase1Proposal.setHashingAlgorithm(toIkeAuthenticationAlgorithm(hashing_algorithm.getValue()));
          ikePhase1Proposal.setDiffieHellmanGroup(
                  toDiffieHellmanGroup(dhgroup.getValue()));
          ikePhase1Proposal.setEncryptionAlgorithm(
                  toEncryptionAlgorithm(encryption_algorithm.getValue()));
          ikePhase1Proposals.add(ikePhase1Proposal);
        }

      }
    }
    return ikePhase1Proposals;
  }

  private static @Nonnull IkePhase1Key toIkePhase1PreSharedKey(
      IpsecTunnel ipsecTunnel, Ip remoteIdentity, String localInterface) {
    IkePhase1Key ikePhase1Key = new IkePhase1Key();
    ikePhase1Key.setKeyType(IkeKeyType.PRE_SHARED_KEY_UNENCRYPTED);
    ikePhase1Key.setKeyHash(ipsecTunnel.getIkePreSharedKeyHash());
    ikePhase1Key.setRemoteIdentity(remoteIdentity.toIpSpace());
    ikePhase1Key.setLocalInterface(localInterface);
    return ikePhase1Key;
  }

  private static @Nonnull IkePhase1Policy toIkePhase1Policy(
      String vpnId,
      List<String> ikePhase1ProposalNames,
      IkePhase1Key ikePhase1Key,
      Ip remoteIdentity,
      String localInterface) {
    IkePhase1Policy ikePhase1Policy = new IkePhase1Policy(vpnId);
    ikePhase1Policy.setIkePhase1Key(ikePhase1Key);
    ikePhase1Policy.setIkePhase1Proposals(ikePhase1ProposalNames);
    ikePhase1Policy.setRemoteIdentity(remoteIdentity.toIpSpace());
    ikePhase1Policy.setLocalInterface(localInterface);
    return ikePhase1Policy;
  }

  private static @Nonnull List<IpsecPhase2Proposal> toIpsecPhase2Proposal(
      IpsecTunnel ipsecTunnel, Warnings warnings) {
    List<IpsecPhase2Proposal> ipsecPhase2Proposals = new ArrayList<>();
    for (VpnConnection.Value hashing_algorithm : ipsecTunnel.getIpsecAuthProtocol()) {
      for (VpnConnection.Value encryption_algorithm : ipsecTunnel.getIpsecEncryptionProtocol()) {

          IpsecPhase2Proposal ipsecPhase2Proposal = new IpsecPhase2Proposal();

          ipsecPhase2Proposal.setAuthenticationAlgorithm(
                  toIpsecAuthenticationAlgorithm(hashing_algorithm.getValue()));
          ipsecPhase2Proposal.setEncryptionAlgorithm(
                  toEncryptionAlgorithm(encryption_algorithm.getValue()));
          ipsecPhase2Proposal.setProtocols(
                  ImmutableSortedSet.of(toIpsecProtocol(ipsecTunnel.getIpsecProtocol())));
          ipsecPhase2Proposal.setIpsecEncapsulationMode(
                  toIpsecEncapdulationMode(ipsecTunnel.getIpsecMode(), warnings));
          ipsecPhase2Proposals.add(ipsecPhase2Proposal);
      }
    }
    return ipsecPhase2Proposals;
  }

  private static @Nonnull List<IpsecPhase2Policy> toIpsecPhase2Policy(
      IpsecTunnel ipsecTunnel, List<String> ipsecPhase2Proposal) {
    List<IpsecPhase2Policy> ipsecPhase2Policies = new ArrayList<>();
    for (DiffieHellmanGroup dh : ipsecTunnel.getIpsecPerfectForwardSecrecy()
            .stream().map(item -> toDiffieHellmanGroup(item.getValue())).
            collect(ImmutableList.toImmutableList())) {
      IpsecPhase2Policy ipsecPhase2Policy = new IpsecPhase2Policy();
      ipsecPhase2Policy.setPfsKeyGroup(dh);
      ipsecPhase2Policy.setProposals(ipsecPhase2Proposal);
      ipsecPhase2Policies.add(ipsecPhase2Policy);
    }
    return ipsecPhase2Policies;
  }

  /**
   * Sets up what is what needed to establish VPN connections to remote nodes: the underlay VRF,
   * routing export policy to backbone, and the connection to backbone.
   */
  static void initVpnConnectionsInfrastructure(Configuration gwCfg) {
    Vrf underlayVrf = Vrf.builder().setOwner(gwCfg).setName(VPN_UNDERLAY_VRF_NAME).build();

    RoutingPolicy.builder()
        .setName(VPN_TO_BACKBONE_EXPORT_POLICY_NAME)
        .setOwner(gwCfg)
        .setStatements(Collections.singletonList(EXPORT_CONNECTED_STATEMENT))
        .build();

    createBackboneConnection(gwCfg, underlayVrf, VPN_TO_BACKBONE_EXPORT_POLICY_NAME);
  }

  /**
   * Creates the infrastructure for this VPN connection on the gateway. This includes created
   * underlay and IPSec tunnel interfaces, configuring IPSec, and running BGP on the tunnel
   * interfaces.
   *
   * <p>The underlay and overlay VRFs and export/import policies must be instantiated before calling
   * this function.
   */
  void applyToGateway(
      Configuration gwCfg,
      Vrf tunnelVrf,
      @Nullable String exportPolicyName,
      @Nullable String importPolicyName,
      Warnings warnings) {
    ImmutableSortedMap.Builder<String, IkePhase1Policy> ikePhase1PolicyMapBuilder =
        ImmutableSortedMap.naturalOrder();
    ImmutableSortedMap.Builder<String, IkePhase1Key> ikePhase1KeyMapBuilder =
        ImmutableSortedMap.naturalOrder();
    ImmutableSortedMap.Builder<String, IkePhase1Proposal> ikePhase1ProposalMapBuilder =
        ImmutableSortedMap.naturalOrder();
    ImmutableSortedMap.Builder<String, IpsecPhase2Proposal> ipsecPhase2ProposalMapBuilder =
        ImmutableSortedMap.naturalOrder();
    ImmutableSortedMap.Builder<String, IpsecPhase2Policy> ipsecPhase2PolicyMapBuilder =
        ImmutableSortedMap.naturalOrder();
    ImmutableSortedMap.Builder<String, IpsecPeerConfig> ipsecPeerConfigMapBuilder =
        ImmutableSortedMap.naturalOrder();

    if (gwCfg.getVrfs().get(VPN_UNDERLAY_VRF_NAME) == null) {
      warnings.redFlagf("Underlay VRF does not exist on gateway %s", gwCfg.getHostname());
      return;
    }
    if (gwCfg.getVrfs().get(tunnelVrf.getName()) == null) {
      warnings.redFlagf("Tunnel VRF does not exist on gateway %s", gwCfg.getHostname());
      return;
    }

    for (int i = 0; i < _ipsecTunnels.size(); i++) {
      String tunnelId = vpnTunnelId(_vpnConnectionId, i + 1);
      IpsecTunnel ipsecTunnel = _ipsecTunnels.get(i);

      // create representation structures and add to configuration node
      String externalInterfaceName = vpnExternalInterfaceName(tunnelId);
      ConcreteInterfaceAddress externalInterfaceAddress =
          ConcreteInterfaceAddress.create(
              ipsecTunnel.getVgwOutsideAddress(), Prefix.MAX_PREFIX_LENGTH);
      Utils.newInterface(
          externalInterfaceName,
          gwCfg,
          VPN_UNDERLAY_VRF_NAME,
          externalInterfaceAddress,
          "IPSec tunnel " + tunnelId);

      String vpnIfaceName = vpnInterfaceName(tunnelId);
      ConcreteInterfaceAddress vpnInterfaceAddress =
          ConcreteInterfaceAddress.create(
              ipsecTunnel.getVgwInsideAddress(), ipsecTunnel.getVgwInsidePrefixLength());
      Utils.newInterface(
          vpnIfaceName, gwCfg, tunnelVrf.getName(), vpnInterfaceAddress, "VPN " + tunnelId);

      // configure Ipsec
      List<IkePhase1Proposal> ikePhase1Proposals = toIkePhase1Proposal(tunnelId, ipsecTunnel);
      List<String> ikePhase1ProposalNames = new ArrayList<>();
      for (IkePhase1Proposal ikePhase1Proposal : ikePhase1Proposals) {
        ikePhase1ProposalMapBuilder.put(ikePhase1Proposal.getName(), ikePhase1Proposal);
        ikePhase1ProposalNames.add(ikePhase1Proposal.getName());
      }

      IkePhase1Key ikePhase1Key =
          toIkePhase1PreSharedKey(
              ipsecTunnel, ipsecTunnel.getCgwOutsideAddress(), externalInterfaceName);
      ikePhase1KeyMapBuilder.put(tunnelId, ikePhase1Key);
      ikePhase1PolicyMapBuilder.put(
          tunnelId,
          toIkePhase1Policy(
              tunnelId,
              ikePhase1ProposalNames,
              ikePhase1Key,
              ipsecTunnel.getCgwOutsideAddress(),
              externalInterfaceName));
      List<IpsecPhase2Proposal> ipsecPhase2Proposals = toIpsecPhase2Proposal(ipsecTunnel, warnings);
      List<String> ipsecPhase2ProposalNames = new ArrayList<>();
      int count = 0;
      for (IpsecPhase2Proposal ipsecPhase2Proposal : ipsecPhase2Proposals) {
        String ipSecPhase2ProposalName = tunnelId+'-'+count;
        ipsecPhase2ProposalMapBuilder.put(ipSecPhase2ProposalName, ipsecPhase2Proposal);
        ipsecPhase2ProposalNames.add(ipSecPhase2ProposalName);
        count++;
      }
      for (IpsecPhase2Policy policy : toIpsecPhase2Policy(ipsecTunnel, ipsecPhase2ProposalNames) ) {
        String policyName = tunnelId+'-'+count;
        ipsecPhase2PolicyMapBuilder.put(policyName, policy);
        ipsecPeerConfigMapBuilder.put(
                policyName + "-peer_config",
                IpsecStaticPeerConfig.builder()
                        .setTunnelInterface(vpnIfaceName)
                        .setIkePhase1Policy(tunnelId)
                        .setIpsecPolicy(policyName)
                        .setSourceInterface(externalInterfaceName)
                        .setLocalAddress(ipsecTunnel.getVgwOutsideAddress())
                        .setDestinationAddress(ipsecTunnel.getCgwOutsideAddress())
                        .build());
        count++;
      }


      // configure BGP peering
      if (_isBgpConnection) {
        BgpActivePeerConfig.builder()
            .setPeerAddress(ipsecTunnel.getCgwInsideAddress())
            .setRemoteAsns(
                Optional.ofNullable(ipsecTunnel.getCgwBgpAsn())
                    .map(LongSpace::of)
                    .orElse(LongSpace.EMPTY))
            .setBgpProcess(tunnelVrf.getBgpProcess())
            .setLocalAs(ipsecTunnel.getVgwBgpAsn())
            .setLocalIp(ipsecTunnel.getVgwInsideAddress())
            .setIpv4UnicastAddressFamily(
                Ipv4UnicastAddressFamily.builder()
                    .setExportPolicy(exportPolicyName)
                    .setImportPolicy(importPolicyName)
                    .build())
            .build();
      }

      // configure static routes -- this list of routes should be empty in case of transit gateway
      _routes.forEach(
          pfx -> addStaticRoute(gwCfg, toStaticRoute(pfx, ipsecTunnel.getCgwInsideAddress())));
    }

    gwCfg.extendIkePhase1Proposals(ikePhase1ProposalMapBuilder.build());
    gwCfg.extendIkePhase1Keys(ikePhase1KeyMapBuilder.build());
    gwCfg.extendIkePhase1Policies(ikePhase1PolicyMapBuilder.build());
    gwCfg.extendIpsecPhase2Proposals(ipsecPhase2ProposalMapBuilder.build());
    gwCfg.extendIpsecPhase2Policies(ipsecPhase2PolicyMapBuilder.build());
    gwCfg.extendIpsecPeerConfigs(ipsecPeerConfigMapBuilder.build());
  }

  @Nonnull
  String getCustomerGatewayId() {
    return _customerGatewayId;
  }

  @Override
  public String getId() {
    return _vpnConnectionId;
  }

  @Nonnull
  List<IpsecTunnel> getIpsecTunnels() {
    return _ipsecTunnels;
  }

  @Nonnull
  List<Prefix> getRoutes() {
    return _routes;
  }

  boolean getStaticRoutesOnly() {
    return _staticRoutesOnly;
  }

  @Nonnull
  List<VgwTelemetry> getVgwTelemetrys() {
    return _vgwTelemetrys;
  }

  boolean isBgpConnection() {
    return _isBgpConnection;
  }

  @Nonnull
  String getVpnConnectionId() {
    return _vpnConnectionId;
  }

  @Nonnull
  GatewayType getAwsGatewayType() {
    return _awsGatewayType;
  }

  @Nonnull
  String getAwsGatewayId() {
    return _awsGatewayId;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof VpnConnection)) {
      return false;
    }
    VpnConnection that = (VpnConnection) o;
    return _staticRoutesOnly == that._staticRoutesOnly
        && Objects.equals(_customerGatewayId, that._customerGatewayId)
        && Objects.equals(_ipsecTunnels, that._ipsecTunnels)
        && Objects.equals(_isBgpConnection, that._isBgpConnection)
        && Objects.equals(_routes, that._routes)
        && Objects.equals(_vgwTelemetrys, that._vgwTelemetrys)
        && Objects.equals(_vpnConnectionId, that._vpnConnectionId)
        && Objects.equals(_awsGatewayType, that._awsGatewayType)
        && Objects.equals(_awsGatewayId, that._awsGatewayId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        _customerGatewayId,
        _ipsecTunnels,
        _isBgpConnection,
        _routes,
        _staticRoutesOnly,
        _vgwTelemetrys,
        _vpnConnectionId,
        _awsGatewayType.ordinal(),
        _awsGatewayId);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("_customerGatewayId", _customerGatewayId)
        .add("_ipsecTunnels", _ipsecTunnels)
        .add("_isBgpConnection", _isBgpConnection)
        .add("_routes", _routes)
        .add("_staticRoutesOnly", _staticRoutesOnly)
        .add("_vgwTelemetrys", _vgwTelemetrys)
        .add("_vpnConnectionId", _vpnConnectionId)
        .add("_awsGatewayType", _awsGatewayType)
        .add("_awsGatewayId", _awsGatewayId)
        .toString();
  }
}
