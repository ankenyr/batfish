package org.batfish.representation.aws;

import static com.google.common.base.Preconditions.checkArgument;
import static org.batfish.datamodel.NamedPort.EPHEMERAL_HIGHEST;
import static org.batfish.datamodel.NamedPort.EPHEMERAL_LOWEST;
import static org.batfish.representation.aws.AwsLocationInfoUtils.INFRASTRUCTURE_LOCATION_INFO;
import static org.batfish.representation.aws.Subnet.NLB_INSTANCE_TARGETS_IFACE_SUFFIX;
import static org.batfish.representation.aws.TargetGroup.Type.IP;
import static org.batfish.representation.aws.Utils.addNodeToSubnet;
import static org.batfish.representation.aws.Utils.checkNonNull;
import static org.batfish.representation.aws.Utils.createPublicIpsRefBook;
import static org.batfish.representation.aws.Utils.interfaceNameToRemote;
import static org.batfish.representation.aws.Utils.toStaticRoute;
import static org.batfish.specifier.Location.interfaceLinkLocation;
import static org.batfish.specifier.Location.interfaceLocation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import org.batfish.common.Warnings;
import org.batfish.datamodel.AclLine;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.DeviceModel;
import org.batfish.datamodel.ExprAclLine;
import org.batfish.datamodel.FirewallSessionInterfaceInfo;
import org.batfish.datamodel.FirewallSessionInterfaceInfo.Action;
import org.batfish.datamodel.HeaderSpace;
import org.batfish.datamodel.Interface;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.IpWildcard;
import org.batfish.datamodel.LineAction;
import org.batfish.datamodel.StaticRoute;
import org.batfish.datamodel.TraceElement;
import org.batfish.datamodel.acl.MatchHeaderSpace;
import org.batfish.datamodel.acl.TrueExpr;
import org.batfish.datamodel.transformation.ApplyAll;
import org.batfish.datamodel.transformation.ApplyAny;
import org.batfish.datamodel.transformation.Transformation;
import org.batfish.datamodel.transformation.TransformationStep;
import org.batfish.representation.aws.LoadBalancerListener.ActionType;
import org.batfish.representation.aws.LoadBalancerListener.DefaultAction;
import org.batfish.representation.aws.LoadBalancerListener.Listener;
import org.batfish.representation.aws.LoadBalancerTargetHealth.HealthState;
import org.batfish.representation.aws.LoadBalancerTargetHealth.TargetHealthDescription;

/**
 * Represents an elastic load balancer v2 https://docs.aws.amazon.com/elasticloadbalancing/.
 *
 * <p>We currently only support network load balancer (not application)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@ParametersAreNonnullByDefault
public final class LoadBalancer implements AwsVpcEntity, Serializable {

  enum Scheme {
    INTERNAL,
    INTERNET_FACING
  }

  enum Type {
    APPLICATION,
    NETWORK
  }

  /** Protocols supported by elastic load balancers */
  public enum Protocol {
    HTTP,
    HTTPS,
    TCP,
    TLS,
    UDP,
    TCP_UDP
  }

  /** Regex for load balancer ARN. Used to find the interface in {@link #findMyInterface}. */
  static final Pattern LOAD_BALANCER_ARN_PATTERN =
      Pattern.compile("^arn:aws:elasticloadbalancing:[^:]+:[0-9]+:loadbalancer\\/(.+)$");

  /** The prefix is that used for interfaces that belong to load balancer */
  static final String LOAD_BALANCER_INTERFACE_DESCRIPTION_PREFIX = "ELB ";

  /** Name for the filter that permits only packets that will match a listener */
  static final String LISTENER_FILTER_NAME = "~LISTENER~FILTER~";

  /** Name for the filter that drops all packets that the load balancer could not forward */
  static final String FORWARDED_PACKETS_FILTER_NAME = "~FORWARDED~PACKET~FILTER~";

  /** We end the transformation chain with this */
  static final Transformation FINAL_TRANSFORMATION = null;

  @JsonIgnoreProperties(ignoreUnknown = true)
  @ParametersAreNonnullByDefault
  static class AvailabilityZone implements Serializable {

    private final @Nonnull String _subnetId;

    private final @Nonnull String _zoneName;

    @JsonCreator
    private static AvailabilityZone create(
        @JsonProperty(JSON_KEY_SUBNET_ID) @Nullable String subnetId,
        @JsonProperty(JSON_KEY_ZONE_NAME) @Nullable String zoneName) {
      // not parsing "LoadBalancerAddresses" -- assuming that network interfaces cover the info
      checkNonNull(subnetId, JSON_KEY_SUBNET_ID, "Load balancer availability zone");
      checkNonNull(zoneName, JSON_KEY_ZONE_NAME, "Load balancer availability zone");
      return new AvailabilityZone(subnetId, zoneName);
    }

    AvailabilityZone(String subnetId, String zoneName) {
      _subnetId = subnetId;
      _zoneName = zoneName;
    }

    public @Nonnull String getSubnetId() {
      return _subnetId;
    }

    public @Nonnull String getZoneName() {
      return _zoneName;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof AvailabilityZone)) {
        return false;
      }
      AvailabilityZone that = (AvailabilityZone) o;
      return _subnetId.equals(that._subnetId) && _zoneName.equals(that._zoneName);
    }

    @Override
    public int hashCode() {
      return Objects.hash(_subnetId, _zoneName);
    }

    @Override
    public String toString() {
      return MoreObjects.toStringHelper(this)
          .add("_subnetId", _subnetId)
          .add("_zoneName", _zoneName)
          .toString();
    }
  }

  private @Nonnull String _arn;

  private final @Nonnull List<AvailabilityZone> _availabilityZones;

  private final @Nonnull String _dnsName;

  private final @Nonnull String _name;

  private final @Nonnull Scheme _scheme;

  private final @Nonnull Type _type;

  private final @Nonnull String _vpcId;

  @JsonCreator
  private static LoadBalancer create(
      @JsonProperty(JSON_KEY_LOAD_BALANCER_ARN) @Nullable String arn,
      @JsonProperty(JSON_KEY_AVAILABILITY_ZONES) @Nullable List<AvailabilityZone> availabilityZones,
      @JsonProperty(JSON_KEY_DNS_NAME) @Nullable String dnsName,
      @JsonProperty(JSON_KEY_LOAD_BALANCER_NAME) @Nullable String name,
      @JsonProperty(JSON_KEY_SCHEME) @Nullable String scheme,
      @JsonProperty(JSON_KEY_TYPE) @Nullable String type,
      @JsonProperty(JSON_KEY_VPC_ID) @Nullable String vpcId) {
    checkNonNull(arn, JSON_KEY_LOAD_BALANCER_ARN, "LoadBalancer");
    checkNonNull(availabilityZones, JSON_KEY_AVAILABILITY_ZONES, "LoadBalancer");
    checkNonNull(dnsName, JSON_KEY_DNS_NAME, "LoadBalancer");
    checkNonNull(name, JSON_KEY_LOAD_BALANCER_NAME, "LoadBalancer");
    checkNonNull(scheme, JSON_KEY_SCHEME, "LoadBalancer");
    checkNonNull(type, JSON_KEY_TYPE, "LoadBalancer");
    checkNonNull(vpcId, JSON_KEY_VPC_ID, "LoadBalancer");

    return new LoadBalancer(
        arn,
        availabilityZones,
        dnsName,
        name,
        Scheme.valueOf(scheme.toUpperCase().replace('-', '_')),
        Type.valueOf(type.toUpperCase()),
        vpcId);
  }

  public LoadBalancer(
      String arn,
      List<AvailabilityZone> availabilityZones,
      String dnsName,
      String name,
      Scheme scheme,
      Type type,
      String vpcId) {
    _arn = arn;
    _availabilityZones = availabilityZones;
    _dnsName = dnsName;
    _name = name;
    _scheme = scheme;
    _type = type;
    _vpcId = vpcId;
  }

  List<Configuration> toConfigurationNodes(
      ConvertedConfiguration awsConfiguration, Region region, Warnings warnings) {
    if (_type == Type.APPLICATION) {
      warnings.redFlag("Application load balancer is not currently supported");
      return ImmutableList.of();
    }
    List<Configuration> configurations = new LinkedList<>();
    _availabilityZones.forEach(
        zone -> configurations.add(toConfigurationNode(zone, awsConfiguration, region, warnings)));
    return configurations;
  }

  /** Creates configuration node corresponding to one availability zone */
  @VisibleForTesting
  Configuration toConfigurationNode(
      AvailabilityZone availabilityZone,
      ConvertedConfiguration awsConfiguration,
      Region region,
      Warnings warnings) {
    Configuration cfgNode =
        Utils.newAwsConfiguration(
            getNodeId(_dnsName, availabilityZone.getZoneName()),
            "aws",
            DeviceModel.AWS_ELB_NETWORK);
    cfgNode.setHumanName(_name);
    cfgNode.getVendorFamily().getAws().setVpcId(_vpcId);
    cfgNode.getVendorFamily().getAws().setSubnetId(availabilityZone.getSubnetId());
    cfgNode.getVendorFamily().getAws().setRegion(region.getName());

    // Add static routes to any instance targets
    getInstanceTargetStaticRoutes(
            awsConfiguration.getNlbsToInstanceTargets().get(_arn), availabilityZone.getSubnetId())
        .forEach(staticRoute -> Utils.addStaticRoute(cfgNode, staticRoute));

    Optional<NetworkInterface> networkInterface =
        findMyInterface(availabilityZone.getSubnetId(), _arn, region);
    if (!networkInterface.isPresent()) {
      warnings.redFlagf(
          "Network interface not found for load balancer %s (%s) in subnet %s.",
          _name, _arn, availabilityZone.getSubnetId());
      return cfgNode;
    }
    Subnet subnet = region.getSubnets().get(availabilityZone.getSubnetId());
    Interface viIface =
        addNodeToSubnet(cfgNode, networkInterface.get(), subnet, awsConfiguration, warnings);

    LoadBalancerAttributes loadBalancerAttributes = region.getLoadBalancerAttributes().get(_arn);
    if (loadBalancerAttributes == null) {
      warnings.redFlagf(
          "Attributes not found for load balancer %s (%s). Assuming that cross zone load"
              + " balancing is disabled.",
          _name, _arn);
    }
    boolean crossZoneLoadBalancing =
        loadBalancerAttributes != null && loadBalancerAttributes.getCrossZoneLoadBalancing();

    List<Listener> listeners = ImmutableList.of();
    LoadBalancerListener lbListener = region.getLoadBalancerListeners().get(_arn);
    if (lbListener != null) {
      listeners = lbListener.getListeners();
    } else {
      warnings.redFlagf("Listeners not found for load balancer %s (%s).", _name, _arn);
    }

    IpAccessList incomingFilter = computeListenerFilter(listeners);
    viIface.setIncomingFilter(incomingFilter);
    cfgNode.getIpAccessLists().put(incomingFilter.getName(), incomingFilter);

    installTransformations(
        viIface,
        getEnabledTargetZones(availabilityZone, crossZoneLoadBalancing, _availabilityZones),
        listeners,
        region,
        warnings);

    IpAccessList defaultFilter =
        computeNotForwardedFilter(networkInterface.get().getPrivateIpAddresses());
    viIface.setPostTransformationIncomingFilter(defaultFilter);
    cfgNode.getIpAccessLists().put(defaultFilter.getName(), defaultFilter);

    createPublicIpsRefBook(Collections.singleton(networkInterface.get()), cfgNode);

    // Create LocationInfo the interface
    cfgNode.setLocationInfo(
        ImmutableMap.of(
            interfaceLocation(viIface),
            INFRASTRUCTURE_LOCATION_INFO,
            interfaceLinkLocation(viIface),
            INFRASTRUCTURE_LOCATION_INFO));

    return cfgNode;
  }

  /**
   * Creates static routes to the IP of each of the given {@code instanceTargets} via subnet {@code
   * lbSubnetId} (that is, using an interface to that subnet's instance target VRF as their next
   * hop). The instance targets will be in the load balancer's VPC, but may not be in the given
   * subnet's availability zone.
   */
  @VisibleForTesting
  static List<StaticRoute> getInstanceTargetStaticRoutes(
      Collection<Instance> instanceTargets, String lbSubnetId) {
    return instanceTargets.stream()
        .map(
            instance -> {
              String subnetCfgHostname = Subnet.nodeName(lbSubnetId);
              String instanceTargetsIface =
                  interfaceNameToRemote(subnetCfgHostname, NLB_INSTANCE_TARGETS_IFACE_SUFFIX);
              // Guaranteed by isTargetInAnyEnabledAvailabilityZone
              assert instance.getPrimaryPrivateIpAddress() != null;
              return toStaticRoute(
                  instance.getPrimaryPrivateIpAddress().toPrefix(),
                  instanceTargetsIface,
                  AwsConfiguration.LINK_LOCAL_IP);
            })
        .collect(ImmutableList.toImmutableList());
  }

  @VisibleForTesting
  void installTransformations(
      Interface viIface,
      Set<String> enabledTargetZones,
      List<Listener> listeners,
      Region region,
      Warnings warnings) {
    if (viIface.getConcreteAddress() != null) { // May be null if we couldn't find a usable address
      List<LoadBalancerTransformation> listenerTransformations =
          listeners.stream()
              .map(
                  listener ->
                      computeListenerTransformation(
                          listener,
                          viIface.getConcreteAddress().getIp(),
                          enabledTargetZones,
                          region,
                          warnings))
              .filter(Objects::nonNull)
              .collect(ImmutableList.toImmutableList());

      viIface.setIncomingTransformation(chainListenerTransformations(listenerTransformations));
    }
    viIface.setFirewallSessionInterfaceInfo(
        new FirewallSessionInterfaceInfo(
            Action.FORWARD_OUT_IFACE, ImmutableList.of(viIface.getName()), null, null));
  }

  /**
   * Gets {@link LoadBalancerTransformation} corresponding to the given {@code listener}. The
   * listener has match conditions and a sequence of actions. The first valid action of type forward
   * is used for the returned transformation.
   *
   * @return null if we cannot build a valid transformation, e.g., the listener protocol for
   *     incoming packets is not supported or none of the targets are valid.
   */
  @VisibleForTesting
  @Nullable
  LoadBalancerTransformation computeListenerTransformation(
      LoadBalancerListener.Listener listener,
      Ip loadBalancerIp,
      Set<String> enabledTargetZones,
      Region region,
      Warnings warnings) {
    try {
      HeaderSpace matchHeaderSpace = listener.getMatchingHeaderSpace();

      Optional<DefaultAction> forwardingAction =
          listener.getDefaultActions().stream()
              .filter(defaultAction -> defaultAction.getType() == ActionType.FORWARD)
              .findFirst();
      if (!forwardingAction.isPresent()) {
        warnings.redFlagf(
            "No forwarding action found for listener %s of load balancer %s (%s)",
            listener, _arn, _name);
        return null;
      }

      TransformationStep transformationStep =
          computeTargetGroupTransformationStep(
              forwardingAction.get().getTargetGroupArn(),
              loadBalancerIp,
              enabledTargetZones,
              region,
              warnings);

      if (transformationStep == null) {
        // no need to warn here. computerTargetGroupTransformationStep does it
        return null;
      }

      return new LoadBalancerTransformation(
          new MatchHeaderSpace(matchHeaderSpace), transformationStep);
    } catch (Exception e) {
      warnings.redFlagf(
          "Failed to compute listener transformation for listener %s of load balancer %s (%s):"
              + " %s",
          listener, _arn, _name, Throwables.getStackTraceAsString(e));
      return null;
    }
  }

  /**
   * Returns the set of active {@link TargetHealthDescription} for the given {@link
   * LoadBalancerTargetHealth}, and optionally files warnings. Note that requests are normally only
   * routed to healthy targets, but if there are no healthy targets, requests will be routed to all
   * targets in enabled availability zones:
   * https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-health-checks.html
   */
  static @Nonnull Set<TargetHealthDescription> getActiveTargets(
      LoadBalancerTargetHealth targetHealth,
      TargetGroup targetGroup,
      Set<String> enabledTargetZones,
      Region region,
      boolean fileWarnings,
      @Nullable Warnings warnings) {
    checkArgument(
        !fileWarnings || warnings != null, "Can't file warnings because warnings is null");

    Set<TargetHealthDescription> enabledTargets =
        targetHealth.getTargetHealthDescriptions().stream()
            .filter(
                desc ->
                    isTargetInValidAvailabilityZone(
                        desc, targetGroup.getTargetType(), enabledTargetZones, region))
            .collect(ImmutableSet.toImmutableSet());
    if (enabledTargets.isEmpty()) {
      if (fileWarnings) {
        warnings.redFlagf(
            "No targets found in enabled availability zone(s) for target group ARN %s",
            targetGroup.getId());
      }
      return ImmutableSet.of();
    }

    Set<TargetHealthDescription> healthyTargets =
        enabledTargets.stream()
            .filter(desc -> desc.getTargetHealth().getState() == HealthState.HEALTHY)
            .collect(ImmutableSet.toImmutableSet());

    // https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-health-checks.html
    // If there are no enabled Availability Zones with a healthy target in each target group,
    // requests are routed to targets in all enabled Availability Zones.
    return healthyTargets.isEmpty() ? enabledTargets : healthyTargets;
  }

  /**
   * Gets {@link TransformationStep} for a {@link TargetGroup}. The load balancer sprays packets
   * across valid targets in the group. Validity is based on target health and zone criteria.
   *
   * @return null if a valid transformation step could not be constructed
   */
  @VisibleForTesting
  static @Nullable TransformationStep computeTargetGroupTransformationStep(
      String targetGroupArn,
      Ip loadBalancerIp,
      Set<String> enabledTargetZones,
      Region region,
      Warnings warnings) {
    TargetGroup targetGroup = region.getTargetGroups().get(targetGroupArn);
    if (targetGroup == null) {
      warnings.redFlagf("Target group ARN %s not found", targetGroupArn);
      return null;
    }

    LoadBalancerTargetHealth targetHealths =
        region.getLoadBalancerTargetHealths().get(targetGroupArn);
    if (targetHealths == null) {
      warnings.redFlagf(
          "Target health information not found for target group ARN %s", targetGroupArn);
      return null;
    }

    Set<TargetHealthDescription> activeTargets =
        getActiveTargets(targetHealths, targetGroup, enabledTargetZones, region, true, warnings);

    Set<TransformationStep> transformationSteps =
        activeTargets.stream()
            .map(
                desc ->
                    computeTargetTransformationStep(
                        desc.getTarget(),
                        targetGroup.getTargetType(),
                        loadBalancerIp,
                        region,
                        warnings))
            .filter(Objects::nonNull)
            .collect(ImmutableSet.toImmutableSet());

    if (transformationSteps.isEmpty()) {
      // warning logged by computeTargetTransformationStep
      return null;
    }

    return new ApplyAny(transformationSteps);
  }

  /**
   * Gets the target IP for the given {@link LoadBalancerTarget}. Assumes that target validity has
   * already been checked with {@link #isTargetInValidAvailabilityZone(TargetHealthDescription,
   * TargetGroup.Type, Set, Region)}.
   */
  static @Nullable Ip getTargetIp(
      LoadBalancerTarget target, TargetGroup.Type targetGroupType, Region region) {
    return targetGroupType.equals(IP)
        ? Ip.parse(target.getId())
        // instance must exist since this target is valid (see isTargetInAnyEnabledAvailabilityZone)
        : region.getInstances().get(target.getId()).getPrimaryPrivateIpAddress();
  }

  /**
   * Returns the transformation step corresponding to {@code target}. This method assumes that the
   * target is valid.
   *
   * @return The transformation step or null if the Ip of the target cannot be determined.
   */
  @VisibleForTesting
  static @Nullable TransformationStep computeTargetTransformationStep(
      LoadBalancerTarget target,
      TargetGroup.Type targetGroupType,
      Ip loadBalancerIp,
      Region region,
      Warnings warnings) {
    Ip targetIp = getTargetIp(target, targetGroupType, region);
    if (targetIp == null) {
      warnings.redFlagf("Could not determine IP for load balancer target %s", target);
      return null;
    }
    TransformationStep transformDstIp = TransformationStep.assignDestinationIp(targetIp, targetIp);
    TransformationStep transformDstPort =
        TransformationStep.assignDestinationPort(target.getPort(), target.getPort());
    return switch (targetGroupType) {
      case INSTANCE ->
          // No source NAT for instance targets
          new ApplyAll(transformDstIp, transformDstPort);
      case IP ->
          new ApplyAll(
              TransformationStep.assignSourceIp(loadBalancerIp, loadBalancerIp),
              TransformationStep.assignSourcePort(
                  EPHEMERAL_LOWEST.number(), EPHEMERAL_HIGHEST.number()),
              transformDstIp,
              transformDstPort);
    };
  }

  /**
   * A target is in a valid zone for this load balancer if it is either in zone "all" or one of the
   * enabled zones.
   */
  @VisibleForTesting
  static boolean isTargetInValidAvailabilityZone(
      TargetHealthDescription targetHealthDescription,
      TargetGroup.Type targetType,
      Set<String> enabledTargetZones,
      Region region) {
    return switch (targetType) {
      case IP ->
          "all".equals(targetHealthDescription.getTarget().getAvailabilityZone())
              || enabledTargetZones.contains(
                  targetHealthDescription.getTarget().getAvailabilityZone());
      case INSTANCE -> {
        Instance instance = region.getInstances().get(targetHealthDescription.getTarget().getId());
        if (instance == null) {
          yield false;
        }
        Subnet subnet = region.getSubnets().get(instance.getSubnetId());
        yield subnet != null && enabledTargetZones.contains(subnet.getAvailabilityZone());
      }
    };
  }

  /** Chains the provided list of transformations. */
  @VisibleForTesting
  static @Nonnull Transformation chainListenerTransformations(
      List<LoadBalancerTransformation> listenerTransformations) {
    Transformation tailTransformation = FINAL_TRANSFORMATION;
    for (int index = listenerTransformations.size() - 1; index >= 0; index--) {
      tailTransformation = listenerTransformations.get(index).toTransformation(tailTransformation);
    }
    return tailTransformation;
  }

  /**
   * Returns a filter that permits packets for listeners with a forwarding action and denies all
   * packets that do not match a listener or match a non-forwarding listener
   */
  @VisibleForTesting
  static IpAccessList computeListenerFilter(List<Listener> listeners) {
    List<AclLine> aclLines =
        listeners.stream()
            // consider only listeners with a forwarding action
            .filter(
                listener ->
                    listener.getDefaultActions().stream()
                        .anyMatch(action -> action.getType() == ActionType.FORWARD))
            .map(
                listener ->
                    ExprAclLine.builder()
                        .setTraceElement(getTraceElementForMatchedListener(listener.getId()))
                        .setMatchCondition(new MatchHeaderSpace(listener.getMatchingHeaderSpace()))
                        .setAction(LineAction.PERMIT)
                        .setName("Listener " + listener.getId())
                        .build())
            .collect(ImmutableList.toImmutableList());
    return IpAccessList.builder()
        .setName(LISTENER_FILTER_NAME)
        .setLines(
            new ImmutableList.Builder<AclLine>()
                .addAll(aclLines)
                .add(
                    ExprAclLine.builder()
                        .setTraceElement(getTraceElementForNoMatchedListener())
                        .setMatchCondition(TrueExpr.INSTANCE)
                        .setAction(LineAction.DENY)
                        .setName("Default deny")
                        .build())
                .build())
        .build();
  }

  @VisibleForTesting
  static TraceElement getTraceElementForMatchedListener(String listenerArn) {
    return TraceElement.of("Matched listener " + listenerArn);
  }

  @VisibleForTesting
  static TraceElement getTraceElementForNoMatchedListener() {
    return TraceElement.of("Did not match any forwarding listeners");
  }

  /**
   * The computed filter rejects all packets that match the network interface's addresses. The idea
   * is that all packets addressed to the load balancer (whose interface is provided as an argument)
   * are dropped if they were not transformed and thus not forwarded. We are relying on the fact
   * that all successfully transformed packets have an IP address different from that of the load
   * balancer.
   */
  @VisibleForTesting
  static IpAccessList computeNotForwardedFilter(
      List<PrivateIpAddress> loadBalancerInterfaceAddresses) {
    return IpAccessList.builder()
        .setName(FORWARDED_PACKETS_FILTER_NAME)
        .setLines(
            ExprAclLine.builder()
                // since we have a filter that permits only packets for valid listeners, all
                // untransformed packets are those for which we didn't find a valid target
                .setTraceElement(getTraceElementForNotForwardedPackets())
                .setMatchCondition(
                    new MatchHeaderSpace(
                        HeaderSpace.builder()
                            .setDstIps(
                                loadBalancerInterfaceAddresses.stream()
                                    .map(privateIp -> IpWildcard.create(privateIp.getPrivateIp()))
                                    .collect(ImmutableList.toImmutableList()))
                            .build()))
                .setAction(LineAction.DENY)
                .setName("Deny packets without a valid target")
                .build(),
            ExprAclLine.builder()
                .setTraceElement(getTraceElementForForwardedPackets())
                .setMatchCondition(TrueExpr.INSTANCE)
                .setAction(LineAction.PERMIT)
                .setName("Permit packets with valid targets")
                .build())
        .build();
  }

  @VisibleForTesting
  static TraceElement getTraceElementForForwardedPackets() {
    return TraceElement.of("Forwarded to a target");
  }

  @VisibleForTesting
  static TraceElement getTraceElementForNotForwardedPackets() {
    return TraceElement.of("No valid (healthy, within availability zone) target found");
  }

  /**
   * Finds the interface that the load balancer uses inside the given subnet.
   *
   * <p>Example arn is
   * 'arn:aws:elasticloadbalancing:us-east-2:554773406868:loadbalancer/net/lb-lb/6f57a43b75d8f2c1'.
   * The regex extracts 'net/lb-lb/6f57a43b75d8f2c1' and uses that to join with interface
   * descriptions which are like 'ELB net/lb-lb/6f57a43b75d8f2c1'.
   * https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html#availability-zones
   */
  @VisibleForTesting
  static Optional<NetworkInterface> findMyInterface(String subnetId, String arn, Region region) {
    Matcher matcher = LOAD_BALANCER_ARN_PATTERN.matcher(arn);
    if (!matcher.matches()) {
      return Optional.empty();
    }
    String matchString = matcher.group(1);
    return region.getNetworkInterfaces().values().stream()
        .filter(
            iface ->
                iface
                        .getDescription()
                        .equals(LOAD_BALANCER_INTERFACE_DESCRIPTION_PREFIX + matchString)
                    && iface.getSubnetId().equals(subnetId))
        .findAny();
  }

  static String getNodeId(String dnsName, String availabilityZoneName) {
    return String.format("%s-%s", availabilityZoneName, dnsName);
  }

  /**
   * Returns all the zones to which the LB instance in {@code instanceZone} will send packets. The
   * result depends on whether cross zone load balancing is enabled for the LB.
   */
  @VisibleForTesting
  static Set<String> getEnabledTargetZones(
      AvailabilityZone instanceZone,
      boolean crossZoneLoadBalancing,
      List<AvailabilityZone> allEnabledZones) {
    return crossZoneLoadBalancing
        ? allEnabledZones.stream()
            .map(zone -> zone.getZoneName())
            .collect(ImmutableSet.toImmutableSet())
        : ImmutableSet.of(instanceZone.getZoneName());
  }

  @Override
  public String getId() {
    return _arn;
  }

  public @Nonnull List<AvailabilityZone> getAvailabilityZones() {
    return _availabilityZones;
  }

  public @Nonnull String getDnsName() {
    return _dnsName;
  }

  public @Nonnull String getName() {
    return _name;
  }

  public @Nonnull Scheme getScheme() {
    return _scheme;
  }

  public @Nonnull Type getType() {
    return _type;
  }

  public @Nonnull String getVpcId() {
    return _vpcId;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof LoadBalancer)) {
      return false;
    }
    LoadBalancer that = (LoadBalancer) o;
    return _arn.equals(that._arn)
        && _availabilityZones.equals(that._availabilityZones)
        && Objects.equals(_dnsName, that._dnsName)
        && Objects.equals(_name, that._name)
        && _scheme == that._scheme
        && _type == that._type
        && _vpcId.equals(that._vpcId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(_arn, _availabilityZones, _dnsName, _name, _scheme, _type, _vpcId);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("_arn", _arn)
        .add("_availabilityZones", _availabilityZones)
        .add("_dnsName", _dnsName)
        .add("_name", _name)
        .add("_scheme", _scheme)
        .add("_type", _type)
        .add("_vpcId", _vpcId)
        .toString();
  }
}
