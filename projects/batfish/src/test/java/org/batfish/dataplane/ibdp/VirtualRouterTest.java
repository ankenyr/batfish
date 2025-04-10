package org.batfish.dataplane.ibdp;

import static org.batfish.common.topology.TopologyUtil.synthesizeL3Topology;
import static org.batfish.datamodel.Configuration.DEFAULT_VRF_NAME;
import static org.batfish.datamodel.bgp.BgpTopologyUtils.initBgpTopology;
import static org.batfish.datamodel.eigrp.EigrpTopologyUtils.initEigrpTopology;
import static org.batfish.datamodel.isis.IsisTopology.initIsisTopology;
import static org.batfish.dataplane.ibdp.VirtualRouter.generateConnectedRoute;
import static org.batfish.dataplane.ibdp.VirtualRouter.generateLocalNullRouteForDownInterface;
import static org.batfish.dataplane.ibdp.VirtualRouter.generateLocalRoute;
import static org.batfish.dataplane.ibdp.VirtualRouter.shouldGenerateConnectedRoute;
import static org.batfish.dataplane.ibdp.VirtualRouter.shouldGenerateLocalRoute;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Function;
import org.batfish.common.topology.GlobalBroadcastNoPointToPoint;
import org.batfish.common.topology.IpOwnersBaseImpl;
import org.batfish.datamodel.AbstractRoute;
import org.batfish.datamodel.AnnotatedRoute;
import org.batfish.datamodel.BgpProcess;
import org.batfish.datamodel.Bgpv4Route;
import org.batfish.datamodel.ConcreteInterfaceAddress;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.ConfigurationFormat;
import org.batfish.datamodel.ConnectedRoute;
import org.batfish.datamodel.ConnectedRouteMetadata;
import org.batfish.datamodel.EigrpExternalRoute;
import org.batfish.datamodel.EigrpInternalRoute;
import org.batfish.datamodel.GeneratedRoute;
import org.batfish.datamodel.Interface;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.IsisRoute;
import org.batfish.datamodel.IsoAddress;
import org.batfish.datamodel.KernelRoute;
import org.batfish.datamodel.LocalRoute;
import org.batfish.datamodel.MainRibVrfLeakConfig;
import org.batfish.datamodel.NetworkFactory;
import org.batfish.datamodel.OriginType;
import org.batfish.datamodel.OspfExternalType1Route;
import org.batfish.datamodel.OspfExternalType2Route;
import org.batfish.datamodel.OspfInterAreaRoute;
import org.batfish.datamodel.OspfIntraAreaRoute;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.RipInternalRoute;
import org.batfish.datamodel.RipProcess;
import org.batfish.datamodel.RoutingProtocol;
import org.batfish.datamodel.StaticRoute;
import org.batfish.datamodel.Topology;
import org.batfish.datamodel.Vrf;
import org.batfish.datamodel.VrfLeakConfig;
import org.batfish.datamodel.bgp.BgpTopology;
import org.batfish.datamodel.eigrp.ClassicMetric;
import org.batfish.datamodel.eigrp.EigrpMetricValues;
import org.batfish.datamodel.eigrp.EigrpMetricVersion;
import org.batfish.datamodel.eigrp.EigrpTopology;
import org.batfish.datamodel.eigrp.WideMetric;
import org.batfish.datamodel.isis.IsisEdge;
import org.batfish.datamodel.isis.IsisInterfaceLevelSettings;
import org.batfish.datamodel.isis.IsisInterfaceMode;
import org.batfish.datamodel.isis.IsisInterfaceSettings;
import org.batfish.datamodel.isis.IsisLevel;
import org.batfish.datamodel.isis.IsisLevelSettings;
import org.batfish.datamodel.isis.IsisNode;
import org.batfish.datamodel.isis.IsisProcess;
import org.batfish.datamodel.isis.IsisTopology;
import org.batfish.datamodel.ospf.OspfMetricType;
import org.batfish.datamodel.route.nh.NextHopDiscard;
import org.batfish.datamodel.route.nh.NextHopInterface;
import org.batfish.datamodel.route.nh.NextHopIp;
import org.batfish.datamodel.routing_policy.RoutingPolicy;
import org.batfish.datamodel.routing_policy.expr.MatchSourceVrf;
import org.batfish.datamodel.routing_policy.statement.If;
import org.batfish.datamodel.routing_policy.statement.Statements;
import org.batfish.datamodel.tracking.PreDataPlaneTrackMethodEvaluator;
import org.batfish.datamodel.tracking.TrackMethodEvaluator;
import org.batfish.dataplane.rib.RibDelta;
import org.batfish.dataplane.rib.RouteAdvertisement;
import org.batfish.dataplane.rib.RouteAdvertisement.Reason;
import org.junit.Test;

/** Tests of {@link VirtualRouter} */
public class VirtualRouterTest {
  /** Make a CISCO IOS router with 3 interfaces named Eth1-Eth3, /16 prefixes on each interface */
  private static final Map<String, ConcreteInterfaceAddress> exampleInterfaceAddresses =
      ImmutableMap.<String, ConcreteInterfaceAddress>builder()
          .put("Ethernet1", ConcreteInterfaceAddress.parse("10.1.0.1/16"))
          .put("Ethernet2", ConcreteInterfaceAddress.parse("10.2.0.1/16"))
          .put("Ethernet3", ConcreteInterfaceAddress.parse("10.3.0.1/16"))
          .build();

  private static void addInterfaces(
      Configuration c, Map<String, ConcreteInterfaceAddress> interfaceAddresses) {
    NetworkFactory nf = new NetworkFactory();
    Interface.Builder ib = nf.interfaceBuilder().setOwner(c).setVrf(c.getDefaultVrf());
    interfaceAddresses.forEach(
        (ifaceName, address) ->
            ib.setName(ifaceName).setAddress(address).setBandwidth(100d).build());
  }

  private static VirtualRouter makeF5VirtualRouter(String hostname) {
    Node n = TestUtils.makeF5Router(hostname);
    return n.getVirtualRouterOrThrow(DEFAULT_VRF_NAME);
  }

  private static VirtualRouter makeA10VirtualRouter(String hostname) {
    Node n = TestUtils.makeA10Router(hostname);
    return n.getVirtualRouterOrThrow(DEFAULT_VRF_NAME);
  }

  private static VirtualRouter makeIosVirtualRouter(String hostname) {
    Node n = TestUtils.makeIosRouter(hostname);
    return n.getVirtualRouterOrThrow(DEFAULT_VRF_NAME);
  }

  private static Set<AbstractRoute> makeOneRouteOfEveryType() {
    return ImmutableSet.of(
        Bgpv4Route.testBuilder()
            .setNetwork(Prefix.parse("1.0.0.0/24"))
            .setOriginatorIp(Ip.parse("8.8.8.8"))
            .setOriginType(OriginType.IGP)
            .setProtocol(RoutingProtocol.IBGP)
            .build(),
        ConnectedRoute.builder()
            .setNetwork(Prefix.parse("1.0.1.0/24"))
            .setNextHopInterface("iface")
            .build(),
        EigrpExternalRoute.testBuilder()
            .setNetwork(Prefix.parse("1.0.2.0/24"))
            .setDestinationAsn(1L)
            .setEigrpMetric(
                WideMetric.builder()
                    .setValues(EigrpMetricValues.builder().setBandwidth(1E8).setDelay(1D).build())
                    .build())
            .setEigrpMetricVersion(EigrpMetricVersion.V1)
            .setProcessAsn(2L)
            .build(),
        EigrpInternalRoute.testBuilder()
            .setNetwork(Prefix.parse("1.0.3.0/24"))
            .setEigrpMetric(
                ClassicMetric.builder()
                    .setValues(EigrpMetricValues.builder().setBandwidth(1E8).setDelay(1D).build())
                    .build())
            .setEigrpMetricVersion(EigrpMetricVersion.V1)
            .setProcessAsn(2L)
            .build(),
        GeneratedRoute.builder().setNetwork(Prefix.parse("1.0.4.0/24")).setAdmin(1).build(),
        IsisRoute.builder()
            .setNetwork(Prefix.parse("1.0.5.0/24"))
            .setLevel(IsisLevel.LEVEL_1)
            .setArea("0")
            .setProtocol(RoutingProtocol.ISIS_L1)
            .setSystemId("id")
            .setNextHop(NextHopDiscard.instance())
            .build(),
        LocalRoute.builder()
            .setNetwork(Prefix.parse("1.0.6.0/24"))
            .setNextHopInterface("iface")
            .setSourcePrefixLength(24)
            .build(),
        OspfInterAreaRoute.builder()
            .setNetwork(Prefix.parse("1.0.7.0/24"))
            .setNextHop(NextHopDiscard.instance())
            .setArea(2L)
            .build(),
        OspfIntraAreaRoute.builder()
            .setNetwork(Prefix.parse("1.0.8.0/24"))
            .setNextHop(NextHopDiscard.instance())
            .setArea(2L)
            .build(),
        OspfExternalType1Route.builder()
            .setNetwork(Prefix.parse("1.0.9.0/24"))
            .setNextHop(NextHopDiscard.instance())
            .setOspfMetricType(OspfMetricType.E1)
            .setLsaMetric(2L)
            .setCostToAdvertiser(3L)
            .setAdvertiser("advertiser")
            .setArea(4L)
            .build(),
        OspfExternalType2Route.builder()
            .setNetwork(Prefix.parse("1.1.0.0/24"))
            .setNextHop(NextHopDiscard.instance())
            .setOspfMetricType(OspfMetricType.E1)
            .setLsaMetric(2L)
            .setCostToAdvertiser(3L)
            .setAdvertiser("advertiser")
            .setArea(4L)
            .build(),
        RipInternalRoute.builder()
            .setNetwork(Prefix.parse("1.1.1.0/24"))
            .setNextHop(NextHopDiscard.instance())
            .build(),
        StaticRoute.testBuilder().setNetwork(Prefix.parse("1.1.2.0/24")).setAdmin(1).build());
  }

  /**
   * Test that {@link VirtualRouter#activateStaticRoutes(TrackMethodEvaluator)} ()} removes a route
   * if a route to its next-hop IP disappears.
   */
  @Test
  public void testActivateStaticRoutesRemoval() {
    VirtualRouter vr = makeIosVirtualRouter("n1");
    addInterfaces(vr.getConfiguration(), exampleInterfaceAddresses);

    ConnectedRoute baseRoute = new ConnectedRoute(Prefix.parse("1.1.1.0/24"), "Ethernet1");
    StaticRoute dependentRoute =
        StaticRoute.testBuilder()
            .setNetwork(Prefix.parse("2.2.2.2/32"))
            .setNextHopIp(Ip.parse("1.1.1.1"))
            .setAdministrativeCost(1)
            .build();

    vr.getConfiguration()
        .getVrfs()
        .get(DEFAULT_VRF_NAME)
        .setStaticRoutes(ImmutableSortedSet.of(dependentRoute));

    // Initial activation
    vr.initConnectedRib();
    vr.initStaticRibs();
    vr.activateStaticRoutes(new PreDataPlaneTrackMethodEvaluator(vr.getConfiguration()));

    // Test: remove baseRoute, rerun activation
    vr.getMainRib().removeRoute(new AnnotatedRoute<>(baseRoute, DEFAULT_VRF_NAME));
    vr.activateStaticRoutes(new PreDataPlaneTrackMethodEvaluator(vr.getConfiguration()));

    // Assert dependent route is not there
    assertThat(vr.getMainRib().getUnannotatedRoutes(), not(hasItem(dependentRoute)));
  }

  /** Check that initialization of Connected RIB is as expected */
  @Test
  public void testInitConnectedRib() {
    // Setup
    VirtualRouter vr = makeIosVirtualRouter(null);
    addInterfaces(vr.getConfiguration(), exampleInterfaceAddresses);
    vr.initRibs();

    // Test
    vr.initConnectedRib();

    // Assert that all interface prefixes have been processed
    assertThat(
        vr.getConnectedRib().getRoutes(),
        equalTo(
            exampleInterfaceAddresses.entrySet().stream()
                .map(
                    e ->
                        new AnnotatedRoute<>(
                            new ConnectedRoute(e.getValue().getPrefix(), e.getKey()),
                            DEFAULT_VRF_NAME))
                .collect(ImmutableSet.toImmutableSet())));
  }

  /** Check that initialization of Kernel RIB is as expected */
  @Test
  public void testInitKernelRib() {
    // Setup
    String hostname = "n1";
    Ip missingRequiredOwnedIp = Ip.parse("10.0.0.0");
    Ip presentRequiredOwnedIp = Ip.parse("10.0.1.0");
    Prefix missingOwnedIpPrefix = Prefix.create(missingRequiredOwnedIp, 24);
    Prefix presentOwnedIpPrefix = Prefix.create(presentRequiredOwnedIp, 24);
    KernelRoute noRequiredOwnedIpRoute = KernelRoute.builder().setNetwork(Prefix.ZERO).build();
    KernelRoute missingRequiredOwnedIpRoute =
        KernelRoute.builder()
            .setNetwork(missingOwnedIpPrefix)
            .setTag(10L)
            .setRequiredOwnedIp(missingRequiredOwnedIp)
            .build();
    KernelRoute presentRequiredOwnedIpRoute =
        KernelRoute.builder()
            .setNetwork(presentOwnedIpPrefix)
            .setTag(11L)
            .setRequiredOwnedIp(presentRequiredOwnedIp)
            .build();
    VirtualRouter vr = makeF5VirtualRouter(hostname);
    vr.getConfiguration()
        .getDefaultVrf()
        .setKernelRoutes(
            ImmutableSortedSet.of(
                noRequiredOwnedIpRoute, missingRequiredOwnedIpRoute, presentRequiredOwnedIpRoute));
    vr.initRibs();

    // Test
    vr.initKernelRoutes();

    // Assert that all kernel routes have been processed
    // The kernel routes not requiring owned IPs should be present in the independent RIB.
    // All others should be present in _kernelConditionalRoutes.
    assertThat(
        vr._independentRib.getRoutes(),
        containsInAnyOrder(vr.annotateRoute(noRequiredOwnedIpRoute)));
    assertThat(
        vr._kernelConditionalRoutes,
        containsInAnyOrder(missingRequiredOwnedIpRoute, presentRequiredOwnedIpRoute));
  }

  @Test
  public void testShouldActivateKernelRoute() {
    // Setup
    String hostname = "n1";
    Ip missingRequiredOwnedIp = Ip.parse("10.0.0.0");
    Ip presentRequiredOwnedIp = Ip.parse("10.0.1.0");
    Prefix missingOwnedIpPrefix = Prefix.create(missingRequiredOwnedIp, 24);
    Prefix presentOwnedIpPrefix = Prefix.create(presentRequiredOwnedIp, 24);
    KernelRoute missingRequiredOwnedIpRoute =
        KernelRoute.builder()
            .setNetwork(missingOwnedIpPrefix)
            .setTag(10L)
            .setRequiredOwnedIp(missingRequiredOwnedIp)
            .build();
    KernelRoute presentRequiredOwnedIpRoute =
        KernelRoute.builder()
            .setNetwork(presentOwnedIpPrefix)
            .setTag(11L)
            .setRequiredOwnedIp(presentRequiredOwnedIp)
            .build();
    Map<Ip, Map<String, Set<String>>> ipVrfOwners =
        ImmutableMap.of(
            presentRequiredOwnedIp, ImmutableMap.of(hostname, ImmutableSet.of(DEFAULT_VRF_NAME)));
    VirtualRouter vr = makeA10VirtualRouter(hostname);

    // Test
    assertTrue(vr.shouldActivateConditionalKernelRoute(presentRequiredOwnedIpRoute, ipVrfOwners));
    assertFalse(vr.shouldActivateConditionalKernelRoute(missingRequiredOwnedIpRoute, ipVrfOwners));
  }

  /** Check that initialization of Local RIB is as expected */
  @Test
  public void testInitLocalRib() {
    // Setup
    VirtualRouter vr = makeIosVirtualRouter(null);
    addInterfaces(vr.getConfiguration(), exampleInterfaceAddresses);
    vr.initRibs();

    // Test
    vr.initLocalRib();

    // Assert that all interface prefixes have been processed
    assertThat(
        vr._localRib.getRoutes(),
        equalTo(
            exampleInterfaceAddresses.entrySet().stream()
                .filter(e -> e.getValue().getPrefix().getPrefixLength() < Prefix.MAX_PREFIX_LENGTH)
                .map(
                    e ->
                        new AnnotatedRoute<>(
                            new LocalRoute(e.getValue(), e.getKey()), DEFAULT_VRF_NAME))
                .collect(ImmutableSet.toImmutableSet())));
  }

  /** Check that VRF static routes are put into appropriate RIBs upon initialization. */
  @Test
  public void testInitStaticRibs() {
    VirtualRouter vr = makeIosVirtualRouter(null);
    addInterfaces(vr.getConfiguration(), exampleInterfaceAddresses);

    List<StaticRoute> routes =
        ImmutableList.of(
            StaticRoute.testBuilder()
                .setNetwork(Prefix.parse("1.1.1.1/32"))
                .setNextHop(NextHopInterface.of("Ethernet1"))
                .setAdministrativeCost(1)
                .setMetric(0L)
                .setTag(1L)
                .build(),
            StaticRoute.testBuilder()
                .setNetwork(Prefix.parse("2.2.2.2/32"))
                .setNextHop(NextHopIp.of(Ip.parse("9.9.9.8")))
                .setAdministrativeCost(1)
                .setMetric(0L)
                .setTag(1L)
                .build(),
            StaticRoute.testBuilder()
                .setNetwork(Prefix.parse("3.3.3.3/32"))
                .setNextHop(NextHopInterface.of("Ethernet1", Ip.parse("9.9.9.9")))
                .setAdministrativeCost(1)
                .setMetric(0L)
                .setTag(1L)
                .build(),
            StaticRoute.testBuilder()
                .setNetwork(Prefix.parse("4.4.4.4/32"))
                .setNextHop(NextHopDiscard.instance())
                .setAdministrativeCost(1)
                .setMetric(0L)
                .setTag(1L)
                .build());
    vr.getConfiguration()
        .getVrfs()
        .get(DEFAULT_VRF_NAME)
        .setStaticRoutes(ImmutableSortedSet.copyOf(routes));

    // Test
    vr.initStaticRibs();

    assertThat(vr._staticUnconditionalRib.getRoutes(), containsInAnyOrder(routes.get(3)));
    assertThat(
        vr._staticConditionalRib.getRoutes(),
        containsInAnyOrder(routes.get(0), routes.get(1), routes.get(2)));
  }

  @Test
  public void testInitRibsEmpty() {
    VirtualRouter vr = makeIosVirtualRouter(null);

    // We expect the router to have the following RIBs and all of them are empty
    vr.initRibs();

    // Simple RIBs
    assertThat(vr.getConnectedRib().getUnannotatedRoutes(), empty());
    assertThat(vr._staticConditionalRib.getUnannotatedRoutes(), empty());
    assertThat(vr._staticUnconditionalRib.getUnannotatedRoutes(), empty());
    assertThat(vr._independentRib.getUnannotatedRoutes(), empty());

    // RIP RIBs
    assertThat(vr._ripInternalRib.getUnannotatedRoutes(), empty());
    assertThat(vr._ripInternalStagingRib.getUnannotatedRoutes(), empty());
    assertThat(vr._ripRib.getUnannotatedRoutes(), empty());

    // Main RIB
    assertThat(vr.getMainRib().getUnannotatedRoutes(), empty());
  }

  /** Check that initialization of RIP internal routes happens correctly */
  @Test
  public void testRipInitialization() {
    // Incomplete Setup
    VirtualRouter vr = makeIosVirtualRouter(null);
    addInterfaces(vr.getConfiguration(), exampleInterfaceAddresses);
    vr.initRibs();
    vr.initBaseRipRoutes();

    // Check that nothing happens
    assertThat(vr._ripInternalRib.getUnannotatedRoutes(), empty());

    // Complete setup by adding a process
    RipProcess ripProcess = new RipProcess();
    ripProcess.setInterfaces(ImmutableSortedSet.copyOf(exampleInterfaceAddresses.keySet()));
    vr._vrf.setRipProcess(ripProcess);

    vr.initBaseRipRoutes();

    assertThat(
        vr._ripInternalRib.getRoutes(),
        equalTo(
            exampleInterfaceAddresses.entrySet().stream()
                .map(
                    entry ->
                        RipInternalRoute.builder()
                            .setNetwork(entry.getValue().getPrefix())
                            .setNextHop(NextHopInterface.of(entry.getKey()))
                            .setAdmin(
                                RoutingProtocol.RIP.getDefaultAdministrativeCost(
                                    vr.getConfiguration().getConfigurationFormat()))
                            .setMetric(RipProcess.DEFAULT_RIP_COST)
                            .build())
                .collect(ImmutableSet.toImmutableSet())));
  }

  /** Test that the static RIB correctly pulls static routes from the VRF */
  @Test
  public void testStaticRibInit() {
    VirtualRouter vr = makeIosVirtualRouter(null);
    vr.initRibs();
    SortedSet<StaticRoute> routeSet =
        ImmutableSortedSet.of(
            StaticRoute.testBuilder()
                .setNetwork(Prefix.parse("1.1.1.1/32"))
                .setNextHop(NextHopIp.of(Ip.parse("2.2.2.2")))
                .setAdministrativeCost(1)
                .setMetric(0L)
                .setTag(0L)
                .build());
    vr._vrf.setStaticRoutes(routeSet);

    // Test
    vr.initStaticRibs();

    assertThat(vr._staticConditionalRib.getRoutes(), equalTo(routeSet));
  }

  /** Test basic message queuing operations */
  @Test
  public void testQueueDelta() {
    Queue<RouteAdvertisement<AbstractRoute>> q = new ConcurrentLinkedQueue<>();

    // Test queueing empty deltas
    VirtualRouter.queueDelta(q, RibDelta.empty());
    assertThat(q, empty());

    RibDelta<AbstractRoute> delta = RibDelta.empty();
    VirtualRouter.queueDelta(q, delta);
    assertThat(q, empty());

    // Test queueing non-empty delta
    StaticRoute sr1 =
        StaticRoute.testBuilder()
            .setNetwork(Ip.parse("1.1.1.1").toPrefix())
            .setNextHop(NextHopDiscard.instance())
            .setAdministrativeCost(1)
            .setMetric(0L)
            .setTag(1L)
            .build();
    StaticRoute sr2 =
        StaticRoute.testBuilder()
            .setNetwork(Ip.parse("1.1.1.1").toPrefix())
            .setNextHop(NextHopDiscard.instance())
            .setAdministrativeCost(100)
            .setMetric(0L)
            .setTag(1L)
            .build();
    RibDelta.Builder<AbstractRoute> builder = RibDelta.<AbstractRoute>builder().add(sr1);

    // Add one route
    VirtualRouter.queueDelta(q, builder.build());
    assertThat(q, hasSize(1));

    // Repeats are allowed; So existing route + 1 add + 1 remove = 3 total
    builder.remove(sr2, Reason.WITHDRAW);
    VirtualRouter.queueDelta(q, builder.build());
    assertThat(q, hasSize(3));
  }

  /** Test that removed routes are queued before added routes */
  @Test
  public void testQueueDeltaOrder() {
    Queue<RouteAdvertisement<AbstractRoute>> q = new ConcurrentLinkedQueue<>();
    StaticRoute sr1 =
        StaticRoute.testBuilder()
            .setNetwork(Ip.parse("1.1.1.1").toPrefix())
            .setNextHop(NextHopDiscard.instance())
            .setAdministrativeCost(1)
            .setMetric(0L)
            .setTag(1L)
            .build();
    StaticRoute sr2 =
        StaticRoute.testBuilder()
            .setNetwork(Ip.parse("1.1.1.1").toPrefix())
            .setNextHop(NextHopDiscard.instance())
            .setAdministrativeCost(100)
            .setMetric(0L)
            .setTag(1L)
            .build();
    RibDelta.Builder<AbstractRoute> builder = RibDelta.builder();

    // Test queueing empty deltas
    builder.add(sr1).remove(sr2, Reason.WITHDRAW);
    VirtualRouter.queueDelta(q, builder.build());

    // Check queuing order.
    // Note: contains complains about generics, do manual remove/check
    assertThat(q.remove(), equalTo(new RouteAdvertisement<>(sr1)));
    assertThat(q.remove(), equalTo(RouteAdvertisement.withdrawing(sr2)));
    assertThat(q, empty());
  }

  @Test
  public void testInitQueuesAndDeltaBuilders() {
    NetworkFactory nf = new NetworkFactory();
    Configuration.Builder cb =
        nf.configurationBuilder().setConfigurationFormat(ConfigurationFormat.CISCO_IOS);
    Configuration c1 = cb.setHostname("r1").build();
    Configuration c2 = cb.setHostname("r2").build();

    Vrf vrf1 = nf.vrfBuilder().setName(DEFAULT_VRF_NAME).setOwner(c1).build();
    Vrf vrf2 = nf.vrfBuilder().setName(DEFAULT_VRF_NAME).setOwner(c2).build();
    // Set bgp processes and neighbors
    BgpProcess proc1 = BgpProcess.testBgpProcess(Ip.parse("1.1.1.1"));
    vrf1.setBgpProcess(proc1);
    BgpProcess proc2 = BgpProcess.testBgpProcess(Ip.parse("1.1.1.2"));
    vrf2.setBgpProcess(proc2);
    nf.bgpNeighborBuilder()
        .setPeerAddress(Ip.parse("1.1.1.2"))
        .setLocalIp(Ip.parse("1.1.1.1"))
        .setBgpProcess(proc1)
        .setRemoteAs(2L)
        .setLocalAs(1L)
        .build();
    nf.bgpNeighborBuilder()
        .setPeerAddress(Ip.parse("1.1.1.1"))
        .setLocalIp(Ip.parse("1.1.1.2"))
        .setBgpProcess(proc2)
        .setRemoteAs(1L)
        .setLocalAs(2L)
        .build();

    Interface.Builder ib = nf.interfaceBuilder();
    ib.setAddress(ConcreteInterfaceAddress.parse("1.1.1.1/30")).setOwner(c1).setVrf(vrf1).build();
    ib.setAddress(ConcreteInterfaceAddress.parse("1.1.1.2/30")).setOwner(c2).setVrf(vrf2).build();

    Topology topology = synthesizeL3Topology(ImmutableMap.of("r1", c1, "r2", c2));

    Map<String, Configuration> configs = ImmutableMap.of("r1", c1, "r2", c2);
    BgpTopology bgpTopology = BgpTopology.EMPTY;
    IsisTopology isisTopology = initIsisTopology(configs, topology);

    Map<String, Node> nodes =
        ImmutableMap.of(c1.getHostname(), new Node(c1), c2.getHostname(), new Node(c2));

    Map<String, VirtualRouter> vrs =
        nodes.values().stream()
            .map(n -> n.getVirtualRouterOrThrow(DEFAULT_VRF_NAME))
            .collect(
                ImmutableMap.toImmutableMap(
                    vr -> vr.getConfiguration().getHostname(), Function.identity()));
    IsisTopology initialIsisTopology = initIsisTopology(configs, topology);

    EigrpTopology eigrpTopology = initEigrpTopology(configs, topology);
    vrs.values()
        .forEach(
            vr ->
                vr.initForEgpComputationWithNewTopology(
                    TopologyContext.builder()
                        .setBgpTopology(bgpTopology)
                        .setEigrpTopology(eigrpTopology)
                        .setIsisTopology(initialIsisTopology)
                        .build(),
                    PreDataPlaneTrackMethodEvaluator::new));

    // Assert that queues are empty as there are no OSPF, BGP, EIGRP, nor IS-IS processes if the
    // topologies are empty
    vrs.values()
        .forEach(
            vr -> {
              assertThat(vr._bgpRoutingProcess._bgpv4Edges, empty());
              vr._eigrpProcesses
                  .values()
                  .forEach(process -> assertThat(process._incomingExternalRoutes, anEmptyMap()));
              assertThat(vr._isisIncomingRoutes, anEmptyMap());
            });

    // Re-run with non-empty topology
    BgpTopology bgpTopology2 =
        initBgpTopology(configs, new TestIpOwners(configs).getIpVrfOwners(), false, null);
    for (Node n : nodes.values()) {
      n.getVirtualRouterOrThrow(DEFAULT_VRF_NAME)
          .initForEgpComputationWithNewTopology(
              TopologyContext.builder()
                  .setBgpTopology(bgpTopology2)
                  .setEigrpTopology(eigrpTopology)
                  .setIsisTopology(isisTopology)
                  .build(),
              PreDataPlaneTrackMethodEvaluator::new);
    }
    // Assert that queues are initialized
    vrs.values()
        .forEach(
            vr -> {
              assertThat(vr._bgpRoutingProcess._bgpv4Edges, is(notNullValue()));
              assertThat(vr._bgpRoutingProcess._bgpv4Edges, hasSize(1));
            });
  }

  @Test
  public void testInitIsisQueuesAndDeltaBuilders() {
    NetworkFactory nf = new NetworkFactory();
    Configuration.Builder cb =
        nf.configurationBuilder().setConfigurationFormat(ConfigurationFormat.CISCO_IOS);
    Vrf.Builder vb = nf.vrfBuilder().setName(DEFAULT_VRF_NAME);
    IsisLevelSettings levelSettings = IsisLevelSettings.builder().build();
    IsisProcess.Builder isb =
        IsisProcess.builder().setLevel1(levelSettings).setLevel2(levelSettings);
    IsisInterfaceLevelSettings isisInterfaceLevelSettings =
        IsisInterfaceLevelSettings.builder().setMode(IsisInterfaceMode.ACTIVE).build();
    IsisInterfaceSettings isisInterfaceSettings =
        IsisInterfaceSettings.builder()
            .setPointToPoint(true)
            .setLevel1(isisInterfaceLevelSettings)
            .setLevel2(isisInterfaceLevelSettings)
            .build();
    Interface.Builder ib = nf.interfaceBuilder();

    Configuration c1 = cb.build();
    Vrf v1 = vb.setOwner(c1).build();
    // Area: 0001, SystemID: 0100.0000.0000
    isb.setVrf(v1).setNetAddress(new IsoAddress("49.0001.0100.0000.0000.00")).build();
    Interface i1 =
        ib.setOwner(c1)
            .setVrf(v1)
            .setAddress(ConcreteInterfaceAddress.parse("10.0.0.0/31"))
            .build();

    Configuration c2 = cb.build();
    Vrf v2 = vb.setOwner(c2).build();
    // Area: 0001, SystemID: 0100.0000.0001
    isb.setVrf(v2).setNetAddress(new IsoAddress("49.0001.0100.0000.0001.00")).build();
    Interface i2 =
        ib.setOwner(c2)
            .setVrf(v2)
            .setAddress(ConcreteInterfaceAddress.parse("10.0.0.1/31"))
            .build();

    Map<String, Configuration> configs =
        ImmutableMap.of(c1.getHostname(), c1, c2.getHostname(), c2);
    Topology topology = synthesizeL3Topology(configs);
    Map<String, Node> nodes =
        ImmutableMap.of(c1.getHostname(), new Node(c1), c2.getHostname(), new Node(c2));
    Map<String, VirtualRouter> vrs =
        nodes.values().stream()
            .map(n -> n.getVirtualRouterOrThrow(DEFAULT_VRF_NAME))
            .collect(
                ImmutableMap.toImmutableMap(
                    vr -> vr.getConfiguration().getHostname(), Function.identity()));
    IsisTopology initialIsisTopology = initIsisTopology(configs, topology);
    EigrpTopology eigrpTopology = initEigrpTopology(configs, topology);
    vrs.values()
        .forEach(
            vr ->
                vr.initQueuesAndDeltaBuilders(
                    TopologyContext.builder()
                        .setEigrpTopology(eigrpTopology)
                        .setIsisTopology(initialIsisTopology)
                        .build()));

    // Assert that queues are empty as there are no OSPF, BGP, nor IS-IS processes
    vrs.values()
        .forEach(
            vr -> {
              assertThat(vr._isisIncomingRoutes, anEmptyMap());
            });

    // Set IS-IS on interfaces
    i1.setIsis(isisInterfaceSettings);
    i2.setIsis(isisInterfaceSettings);
    IsisTopology updatedIsisTopology = initIsisTopology(configs, topology);

    // Re-run
    vrs.values()
        .forEach(
            vr ->
                vr.initQueuesAndDeltaBuilders(
                    TopologyContext.builder()
                        .setEigrpTopology(eigrpTopology)
                        .setIsisTopology(updatedIsisTopology)
                        .build()));

    // Assert that queues are initialized
    assertThat(
        vrs.get(c1.getHostname())._isisIncomingRoutes.keySet(),
        equalTo(
            ImmutableSet.of(
                new IsisEdge(
                    IsisLevel.LEVEL_1_2,
                    new IsisNode(c2.getHostname(), i2.getName()),
                    new IsisNode(c1.getHostname(), i1.getName())))));
    assertThat(
        vrs.get(c2.getHostname())._isisIncomingRoutes.keySet(),
        equalTo(
            ImmutableSet.of(
                new IsisEdge(
                    IsisLevel.LEVEL_1_2,
                    new IsisNode(c1.getHostname(), i1.getName()),
                    new IsisNode(c2.getHostname(), i2.getName())))));
  }

  @Test
  public void testCrossVrfRouteLeaking() {
    String vrfWithRoutesName = "VRF1";
    String emptyVrfName = "VRF2";
    String importPolicyName = "IMPORT-POLICY";

    /*
    Create configuration containing 2 VRFs:
      - vrfWithRoutes has routes of every type, to ensure all route types get leaked correctly
      - emptyVrf has no routes and is set up to import all routes from vrfWithRoutes
    Tests:
      - ensure initCrossVrfImports() correctly leaks all routes from vrfWithRoutes' main RIB
      - ensure queueCrossVrfImports() correctly leaks all routes from vrfWithRoutes' main RIB delta
    */
    NetworkFactory nf = new NetworkFactory();
    Configuration c =
        // set format to Juniper for consistency since we will use a Juniper-style VRF leak config
        nf.configurationBuilder().setConfigurationFormat(ConfigurationFormat.JUNIPER).build();

    // Create cross-VRF import policy to accept routes from vrfWithRoutes (and reject all others)
    RoutingPolicy.builder()
        .setOwner(c)
        .setName(importPolicyName)
        .setStatements(
            ImmutableList.of(
                new If(
                    new MatchSourceVrf(vrfWithRoutesName),
                    ImmutableList.of(Statements.ExitAccept.toStaticStatement()),
                    ImmutableList.of(Statements.ExitReject.toStaticStatement()))))
        .build();

    // Create VRFs in configuration and set up cross-VRF import VRF and policy for empty one
    nf.vrfBuilder().setOwner(c).setName(vrfWithRoutesName).build();
    nf.vrfBuilder()
        .setOwner(c)
        .setName(emptyVrfName)
        .setVrfLeakConfig(
            VrfLeakConfig.builder(false)
                .addMainRibVrfLeakConfig(
                    MainRibVrfLeakConfig.builder()
                        .setImportFromVrf(vrfWithRoutesName)
                        .setImportPolicy(importPolicyName)
                        .build())
                .build())
        .build();

    // Create a Node based on the configuration and get its VirtualRouters
    Node n = new Node(c);
    VirtualRouter vrWithRoutes = n.getVirtualRouterOrThrow(vrfWithRoutesName);
    VirtualRouter emptyVr = n.getVirtualRouterOrThrow(emptyVrfName);

    // Create routes of every type and inject them into vrWithRoutes' main RIB and main RIB delta
    Set<AnnotatedRoute<AbstractRoute>> annotatedRoutes =
        makeOneRouteOfEveryType().stream()
            .map(r -> new AnnotatedRoute<>(r, vrfWithRoutesName))
            .collect(ImmutableSet.toImmutableSet());
    for (AnnotatedRoute<AbstractRoute> r : annotatedRoutes) {
      vrWithRoutes._mainRibRouteDeltaBuilder.from(vrWithRoutes.getMainRib().mergeRouteGetDelta(r));
    }
    vrWithRoutes.endOfEgpRound();

    // Run initial leaking (i.e. what would happen at beginning of
    // computeNonMonotonicPortionOfDataPlane()); all routes should leak from vrWithRoutes' main RIB
    emptyVr.initCrossVrfQueues();
    emptyVr.initCrossVrfImports();
    emptyVr.processCrossVrfRoutes();
    assertThat(emptyVr.getMainRib().getRoutes(), equalTo(annotatedRoutes));

    // Clear emptyVr's RIB and queues and run intermediate leaking (i.e. what would happen in one
    // computeDependentRoutesIteration()); all routes should leak from vrWithRoutes' main RIB delta
    emptyVr.getMainRib().clear();
    emptyVr.initCrossVrfQueues();
    emptyVr.queueCrossVrfImports();
    emptyVr.processCrossVrfRoutes();
    assertThat(emptyVr.getMainRib().getRoutes(), equalTo(annotatedRoutes));
  }

  @Test
  public void testGenerateConnectedRoute() {
    String nextHopInterface = "Eth0";
    ConcreteInterfaceAddress address = ConcreteInterfaceAddress.parse("1.1.1.1/24");
    Prefix prefix = address.getPrefix();

    assertThat(
        generateConnectedRoute(address, nextHopInterface, null),
        equalTo(
            ConnectedRoute.builder()
                .setNetwork(prefix)
                .setNextHopInterface(nextHopInterface)
                .build()));

    assertThat(
        generateConnectedRoute(
            address, nextHopInterface, ConnectedRouteMetadata.builder().setTag(7).build()),
        equalTo(
            ConnectedRoute.builder()
                .setNetwork(prefix)
                .setNextHopInterface(nextHopInterface)
                .setTag(7L)
                .build()));
  }

  @Test
  public void testGenerateLocalRoute() {
    String nextHopInterface = "Eth0";
    ConcreteInterfaceAddress address = ConcreteInterfaceAddress.parse("1.1.1.1/24");
    Prefix prefix = address.getIp().toPrefix();

    assertThat(
        generateLocalRoute(address, nextHopInterface, null),
        equalTo(
            LocalRoute.builder()
                .setNetwork(prefix)
                .setSourcePrefixLength(address.getNetworkBits())
                .setNextHopInterface(nextHopInterface)
                .build()));

    assertThat(
        generateLocalRoute(
            address, nextHopInterface, ConnectedRouteMetadata.builder().setTag(7).build()),
        equalTo(
            LocalRoute.builder()
                .setNetwork(prefix)
                .setSourcePrefixLength(address.getNetworkBits())
                .setNextHopInterface(nextHopInterface)
                .setTag(7L)
                .build()));
  }

  @Test
  public void testShouldGenerateLocalRoute() {
    assertFalse(shouldGenerateLocalRoute(Prefix.MAX_PREFIX_LENGTH, null));
    assertFalse(
        shouldGenerateLocalRoute(
            Prefix.MAX_PREFIX_LENGTH, ConnectedRouteMetadata.builder().build()));
    assertFalse(
        shouldGenerateLocalRoute(
            Prefix.MAX_PREFIX_LENGTH,
            ConnectedRouteMetadata.builder().setGenerateLocalRoute(false).build()));
    assertTrue(
        shouldGenerateLocalRoute(
            Prefix.MAX_PREFIX_LENGTH,
            ConnectedRouteMetadata.builder().setGenerateLocalRoute(true).build()));

    assertTrue(shouldGenerateLocalRoute(24, null));
    assertTrue(shouldGenerateLocalRoute(24, ConnectedRouteMetadata.builder().build()));
    assertFalse(
        shouldGenerateLocalRoute(
            24, ConnectedRouteMetadata.builder().setGenerateLocalRoute(false).build()));
    assertTrue(
        shouldGenerateLocalRoute(
            24, ConnectedRouteMetadata.builder().setGenerateLocalRoute(true).build()));
  }

  @Test
  public void testShouldGenerateLocalNullRouteIfDown() {
    ConcreteInterfaceAddress addr = ConcreteInterfaceAddress.parse("1.2.3.5/24");
    LocalRoute lr =
        LocalRoute.builder()
            .setNetwork(Prefix.parse("1.2.3.5/32"))
            .setNextHop(NextHopDiscard.instance())
            .setSourcePrefixLength(24)
            .build();

    assertThat(generateLocalNullRouteForDownInterface(addr, null), equalTo(Optional.empty()));
    assertThat(
        generateLocalNullRouteForDownInterface(addr, ConnectedRouteMetadata.builder().build()),
        equalTo(Optional.empty()));
    assertThat(
        generateLocalNullRouteForDownInterface(
            addr, ConnectedRouteMetadata.builder().setGenerateLocalNullRouteIfDown(false).build()),
        equalTo(Optional.empty()));
    assertThat(
        generateLocalNullRouteForDownInterface(
            addr, ConnectedRouteMetadata.builder().setGenerateLocalNullRouteIfDown(true).build()),
        equalTo(Optional.of(lr)));
    assertThat(
        generateLocalNullRouteForDownInterface(
            addr,
            ConnectedRouteMetadata.builder()
                .setGenerateLocalNullRouteIfDown(true)
                .setTag(5L)
                .build()),
        equalTo(Optional.of(lr.toBuilder().setTag(5L).build())));
  }

  @Test
  public void testShouldGenerateConnectedRoute() {
    assertTrue(shouldGenerateConnectedRoute(null));
    assertTrue(shouldGenerateConnectedRoute(ConnectedRouteMetadata.builder().build()));
    assertTrue(
        shouldGenerateConnectedRoute(
            ConnectedRouteMetadata.builder().setGenerateConnectedRoute(true).build()));
    assertFalse(
        shouldGenerateConnectedRoute(
            ConnectedRouteMetadata.builder().setGenerateConnectedRoute(false).build()));
  }

  @Test
  public void testComputeIterationHashCode_identicalInstances() {
    // Two different but identical VirtualRouter instances should have the same hashcode.
    // This guarantees hashcode is implemented for all objects that factor in.
    VirtualRouter vr1 = makeIosVirtualRouter("c1");
    VirtualRouter vr2 = makeIosVirtualRouter("c2");
    // Need to init queues and delta builders to compute hashcode without NPE
    TopologyContext emptyTopology = TopologyContext.builder().build();
    vr1.initQueuesAndDeltaBuilders(emptyTopology);
    vr2.initQueuesAndDeltaBuilders(emptyTopology);

    assertEquals(vr1.computeIterationHashCode(), vr2.computeIterationHashCode());
  }

  @Test
  public void testComputeIterationHashCode_mainRibChange() {
    VirtualRouter vr = makeIosVirtualRouter("c");
    Configuration c = vr.getConfiguration();
    addInterfaces(c, ImmutableMap.of("i", ConcreteInterfaceAddress.parse("1.1.1.1/30")));
    TopologyContext emptyTopology = TopologyContext.builder().build();

    // Init queues and delta builders. This is necessary to compute hashcode without NPE, but
    // will not initialize connected routes.
    vr.initQueuesAndDeltaBuilders(emptyTopology);
    int vrInitialHashcode = vr.computeIterationHashCode();

    // Now init connected routes. This should cause a change in the main RIB.
    vr.initForIgpComputation(emptyTopology);

    assertNotEquals(vrInitialHashcode, vr.computeIterationHashCode());
  }

  private static class TestIpOwners extends IpOwnersBaseImpl {
    protected TestIpOwners(Map<String, Configuration> configurations) {
      super(
          configurations,
          GlobalBroadcastNoPointToPoint.instance(),
          PreDataPlaneTrackMethodEvaluator::new,
          false);
    }
  }
}
