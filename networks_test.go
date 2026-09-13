package ivnp

import (
	"testing"
	"time"

	"gosuda.org/ivnp/overlay"
)

func testRealm() *RealmProfile {
	return &RealmProfile{
		ID: RealmIDFor("test"), Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyExplicitDirect, Routing: RoutingOverlayDirect,
		Publication: PublicationNone, IncludeNative: true,
	}
}

func testFabric(name string, netID uint32) NetworkConfig {
	return IVNPFabricNetwork(name, netID, 8, []string{"127.0.0.1:0"}, nil)
}

func TestNetworkPlanLegacyDefaults(t *testing.T) {
	native, spec, err := networkPlan(DefaultRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	if spec != nil {
		t.Fatal("legacy config produced an overlay spec")
	}
	if native.NetworkID != 2 || native.Name != networkNativeName {
		t.Fatalf("native = %+v", native)
	}
}

func TestNetworkPlanLegacyRealm(t *testing.T) {
	cfg := DefaultRouterConfig()
	cfg.Realm = testRealm()
	_, spec, err := networkPlan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if spec == nil || !spec.Native || spec.Realm.ID != cfg.Realm.ID {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestNetworkPlanLegacyRealmRequiresNative(t *testing.T) {
	cfg := DefaultRouterConfig()
	realm := testRealm()
	realm.IncludeNative = false
	cfg.Realm = realm
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("legacy realm without the native context was accepted")
	}
}

func TestNetworkPlanNetworksRequireRealm(t *testing.T) {
	cfg := DefaultRouterConfig()
	cfg.NetworkID, cfg.NTCP2, cfg.SSU2 = 0, TransportConfig{}, TransportConfig{}
	cfg.Bootstrap, cfg.Exploratory = BootstrapConfig{}, TunnelPoolConfig{}
	cfg.Networks = []NetworkConfig{DefaultI2PNetwork()}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("Networks without Realm was accepted")
	}
}

func TestNetworkPlanRejectsLegacyMixing(t *testing.T) {
	cfg := RouterConfig{
		NetworkID: 2, // legacy field set alongside Networks
		Networks:  []NetworkConfig{DefaultI2PNetwork()},
		Realm:     testRealm(),
		Limits:    DefaultRouterConfig().Limits,
	}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("legacy fields combined with Networks were accepted")
	}
}

func TestNetworkPlanNativeRules(t *testing.T) {
	realm := testRealm()

	// Missing the required "i2p" entry entirely.
	cfg := RouterConfig{
		Networks: []NetworkConfig{testFabric("f", 77)},
		Realm:    realm,
	}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("Networks without a native entry was accepted")
	}

	// An entry with an empty name is rejected.
	bad := DefaultI2PNetwork()
	bad.Name = ""
	cfg.Networks = []NetworkConfig{bad}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("entry with an empty name was accepted")
	}

	// A native entry with a custom non-empty name (e.g. "main" or "public") is valid and accepted.
	custom := DefaultI2PNetwork()
	custom.Name = "main"
	cfg.Networks = []NetworkConfig{custom}
	if planNative, _, err := networkPlan(cfg); err != nil || planNative.Name != "main" {
		t.Fatalf("custom named native entry failed: %v", err)
	}

	// A native entry with the wrong network number.
	bad = DefaultI2PNetwork()
	bad.NetworkID = 99
	cfg.Networks = []NetworkConfig{bad}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("native entry with netId != 2 was accepted")
	}

	// A native entry carrying fabric fields.
	bad = DefaultI2PNetwork()
	bad.Fabric = &FabricDescriptor{ID: FabricIDFor("x"), NetworkID: 77, MaxPeers: 4}
	cfg.Networks = []NetworkConfig{bad}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("native entry with a fabric descriptor was accepted")
	}

	// Two native entries.
	cfg.Networks = []NetworkConfig{DefaultI2PNetwork(), DefaultI2PNetwork()}
	cfg.Networks[1].Name = "i2p"
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("duplicate native entries were accepted")
	}

	// An out-of-range participation value.
	bad = DefaultI2PNetwork()
	bad.Participation = PublicParticipation(99)
	cfg.Networks = []NetworkConfig{bad}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("native entry with an invalid participation was accepted")
	}
}

func TestRouterSettingsMapsParticipationToOperatingRoles(t *testing.T) {
	networksConfig := func(participation PublicParticipation) RouterConfig {
		cfg := DefaultRouterConfig()
		cfg.NetworkID, cfg.NTCP2, cfg.SSU2 = 0, TransportConfig{}, TransportConfig{}
		cfg.Bootstrap, cfg.Exploratory = BootstrapConfig{}, TunnelPoolConfig{}
		native := DefaultI2PNetwork()
		native.Participation = participation
		cfg.Networks = []NetworkConfig{native}
		cfg.Realm = testRealm()
		return cfg
	}
	for _, test := range []struct {
		participation PublicParticipation
		transit       bool
		floodfill     bool
	}{
		{ParticipationOnDemand, false, false},
		{ParticipationWarm, true, false},
		{ParticipationContributor, true, true},
	} {
		operating, _, _, err := routerSettings(networksConfig(test.participation))
		if err != nil {
			t.Fatalf("participation %d settings error = %v", test.participation, err)
		}
		if operating.Router.Transit != test.transit || operating.Router.Floodfill != test.floodfill {
			t.Fatalf("participation %d mapped transit=%t floodfill=%t", test.participation, operating.Router.Transit, operating.Router.Floodfill)
		}
	}

	// A zero participation selects the warm defaults.
	operating, _, _, err := routerSettings(networksConfig(0))
	if err != nil {
		t.Fatal(err)
	}
	if !operating.Router.Transit || operating.Router.Floodfill {
		t.Fatalf("unset participation mapped transit=%t floodfill=%t", operating.Router.Transit, operating.Router.Floodfill)
	}
}

func TestNetworkPlanFabricRules(t *testing.T) {
	realm := testRealm()
	native := DefaultI2PNetwork()

	// A fabric reusing the native name.
	f := testFabric("i2p", 77)
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{native, f}, Realm: realm}); err == nil {
		t.Fatal("fabric named i2p was accepted")
	}

	// A fabric without a descriptor.
	f = testFabric("f", 77)
	f.Fabric = nil
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{native, f}, Realm: realm}); err == nil {
		t.Fatal("fabric without a descriptor was accepted")
	}

	// A fabric claiming the public network number.
	f = testFabric("f", 77)
	f.Fabric.NetworkID = 2
	f.NetworkID = 2
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{native, f}, Realm: realm}); err == nil {
		t.Fatal("fabric with netId 2 was accepted")
	}

	// Entry-level NetworkID disagreeing with the descriptor.
	f = testFabric("f", 77)
	f.NetworkID = 78
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{native, f}, Realm: realm}); err == nil {
		t.Fatal("conflicting entry and descriptor netIds were accepted")
	}

	// Native-only fields on a fabric entry.
	f = testFabric("f", 77)
	f.NTCP2 = DefaultRouterConfig().NTCP2
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{native, f}, Realm: realm}); err == nil {
		t.Fatal("fabric carrying native transport fields was accepted")
	}

	// A malformed listener address.
	f = testFabric("f", 77)
	f.Listeners = []string{"not-an-address"}
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{native, f}, Realm: realm}); err == nil {
		t.Fatal("fabric with a malformed listener was accepted")
	}

	// Duplicate names across kinds.
	f = testFabric("f", 77)
	g := testFabric("f", 88)
	if _, _, err := networkPlan(RouterConfig{Networks: []NetworkConfig{native, f, g}, Realm: realm}); err == nil {
		t.Fatal("duplicate fabric names were accepted")
	}
}

func TestNetworkPlanRealmFabricSelection(t *testing.T) {
	realm := testRealm()
	realm.Fabrics = []string{"missing"}
	cfg := RouterConfig{
		Networks: []NetworkConfig{DefaultI2PNetwork(), testFabric("f", 77)},
		Realm:    realm,
	}
	if _, _, err := networkPlan(cfg); err == nil {
		t.Fatal("realm binding an unknown fabric was accepted")
	}
}

func TestRealmSpecPSKValidation(t *testing.T) {
	realm := testRealm()
	realm.Admission = AdmissionPSK // psk mode without key
	if _, err := realmSpec(realm, nil); err == nil {
		t.Fatal("psk admission without a key was accepted")
	}

	realm = testRealm()
	realm.PSK = []byte("key material") // key under open admission
	if _, err := realmSpec(realm, nil); err == nil {
		t.Fatal("a key under non-psk admission was accepted")
	}

	realm = testRealm()
	realm.ID = RealmID{}
	if _, err := realmSpec(realm, nil); err == nil {
		t.Fatal("realm without an id was accepted")
	}
}

func TestNetworkPlanDualStack(t *testing.T) {
	realm := testRealm()
	realm.Fabrics = []string{"corp"}
	cfg := RouterConfig{
		Networks: []NetworkConfig{DefaultI2PNetwork(), testFabric("corp", 77)},
		Realm:    realm,
	}
	native, spec, err := networkPlan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if native.NetworkID != 2 {
		t.Fatalf("native netId = %d", native.NetworkID)
	}
	if spec == nil || !spec.Native || len(spec.Fabrics) != 1 {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.Fabrics[0].Name != "corp" || spec.Fabrics[0].Descriptor.NetworkID != overlay.WireNetworkID(77) {
		t.Fatalf("fabric = %+v", spec.Fabrics[0])
	}
	if len(spec.Realm.Fabrics) != 1 || spec.Realm.Fabrics[0] != "corp" {
		t.Fatalf("realm fabrics = %v", spec.Realm.Fabrics)
	}
}

func TestResolveNetworkNamesRequiresRealmBound(t *testing.T) {
	bound, unbound := FabricIDFor("bound"), FabricIDFor("stray")
	router := &Router{
		realmFabrics: []FabricID{bound, overlay.NativeI2PFabricID},
		fabricNames: map[string]FabricID{
			"bound": bound, "stray": unbound, "i2p": overlay.NativeI2PFabricID,
		},
	}
	if _, err := router.resolveNetworkNames([]string{"stray"}); err == nil {
		t.Fatal("a configured but unbound fabric name was accepted")
	}
	if _, err := router.resolveNetworkNames([]string{"ghost"}); err == nil {
		t.Fatal("an unknown network name was accepted")
	}
	resolved, err := router.resolveNetworkNames([]string{"bound", "i2p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resolved[bound]; !ok {
		t.Fatal("bound fabric missing from the resolved set")
	}
	if _, ok := resolved[overlay.NativeI2PFabricID]; !ok {
		t.Fatal("native fabric missing from the resolved set")
	}
	if resolved, err := router.resolveNetworkNames(nil); err != nil || resolved != nil {
		t.Fatal("an empty selection must admit every realm-bound fabric")
	}
}

func TestDestinationNetworksRequireOverlay(t *testing.T) {
	// The Networks-without-Overlay check runs before the router's state is
	// consulted, so a zero-value Router exercises it.
	router := &Router{children: make(map[*Destination]struct{})}
	cfg := DefaultDestinationConfig()
	cfg.Networks = []string{"i2p"}
	if _, err := router.NewDestination(t.Context(), cfg); err == nil {
		t.Fatal("Networks without Overlay was accepted")
	}
}

func TestBootstrapEmpty(t *testing.T) {
	if !bootstrapEmpty(BootstrapConfig{}) {
		t.Fatal("zero bootstrap reported non-empty")
	}
	b := BootstrapConfig{RouterInfos: [][]byte{{1}}}
	if bootstrapEmpty(b) {
		t.Fatal("RouterInfos-only bootstrap reported empty")
	}
	b = BootstrapConfig{ReseedTimeout: time.Second}
	if bootstrapEmpty(b) {
		t.Fatal("ReseedTimeout-only bootstrap reported empty")
	}
}

func TestResolveDefaultNetwork(t *testing.T) {
	// 1. DefaultRouterConfig() defaults to "i2p"
	def, err := resolveDefaultNetwork(DefaultRouterConfig())
	if err != nil || def != "i2p" {
		t.Fatalf("DefaultRouterConfig default net = %q, err = %v", def, err)
	}

	// 2. Legacy router config with non-existent DefaultNetwork fails
	cfgLegacyBad := DefaultRouterConfig()
	cfgLegacyBad.DefaultNetwork = "corp"
	if _, err := resolveDefaultNetwork(cfgLegacyBad); err == nil {
		t.Fatal("expected error for non-existent DefaultNetwork in legacy config")
	}

	// 3. Multi-network with single fabric and DefaultNetwork unset defaults to "i2p" if IncludeNative
	realm := testRealm()
	native := DefaultI2PNetwork()
	corp := testFabric("corp", 77)
	cfgDual := RouterConfig{
		Networks: []NetworkConfig{native, corp},
		Realm:    realm,
	}
	def, err = resolveDefaultNetwork(cfgDual)
	if err != nil || def != "i2p" {
		t.Fatalf("dual stack default net = %q, err = %v", def, err)
	}

	// 4. Multi-network with IncludeNative: false defaults to the first IVNPFabric
	privRealm := &RealmProfile{
		ID:            RealmIDFor("priv"),
		Admission:     AdmissionPSK,
		PSK:           []byte("test-psk-12345678901234567890"),
		IncludeNative: false,
	}
	cfgPriv := RouterConfig{
		Networks: []NetworkConfig{native, corp},
		Realm:    privRealm,
	}
	def, err = resolveDefaultNetwork(cfgPriv)
	if err != nil || def != "corp" {
		t.Fatalf("private realm default net = %q, err = %v", def, err)
	}

	// 5. Multi-network with explicit Default: true on fabric
	corpDefault := testFabric("corp", 77)
	corpDefault.Default = true
	cfgFabricDefault := RouterConfig{
		Networks: []NetworkConfig{native, corpDefault},
		Realm:    realm,
	}
	def, err = resolveDefaultNetwork(cfgFabricDefault)
	if err != nil || def != "corp" {
		t.Fatalf("fabric Default:true default net = %q, err = %v", def, err)
	}

	// 6. Multi-network with multiple Default: true fails
	nativeDefault := DefaultI2PNetwork()
	nativeDefault.Default = true
	cfgMultiDefault := RouterConfig{
		Networks: []NetworkConfig{nativeDefault, corpDefault},
		Realm:    realm,
	}
	if _, err := resolveDefaultNetwork(cfgMultiDefault); err == nil {
		t.Fatal("expected error for multiple networks with Default: true")
	}

	// 7. Multi-network with Default: true conflicting with DefaultNetwork fails
	cfgConflict := RouterConfig{
		DefaultNetwork: "i2p",
		Networks:       []NetworkConfig{native, corpDefault},
		Realm:          realm,
	}
	if _, err := resolveDefaultNetwork(cfgConflict); err == nil {
		t.Fatal("expected error for Default: true conflicting with DefaultNetwork")
	}

	// 8. Multi-network with DefaultNetwork explicitly set
	cfgExplicit := RouterConfig{
		DefaultNetwork: "corp",
		Networks:       []NetworkConfig{native, corp},
		Realm:          realm,
	}
	def, err = resolveDefaultNetwork(cfgExplicit)
	if err != nil || def != "corp" {
		t.Fatalf("explicit DefaultNetwork default net = %q, err = %v", def, err)
	}

	// 9. Multi-network with unknown DefaultNetwork fails
	cfgUnknown := RouterConfig{
		DefaultNetwork: "unknown",
		Networks:       []NetworkConfig{native, corp},
		Realm:          realm,
	}
	if _, err := resolveDefaultNetwork(cfgUnknown); err == nil {
		t.Fatal("expected error for unknown DefaultNetwork in multi-network")
	}

	// 10. DefaultNetwork = "ivnp" is valid
	cfgIVNP := RouterConfig{
		DefaultNetwork: "ivnp",
		Networks:       []NetworkConfig{native, corp},
		Realm:          realm,
	}
	def, err = resolveDefaultNetwork(cfgIVNP)
	if err != nil || def != "ivnp" {
		t.Fatalf("ivnp DefaultNetwork default net = %q, err = %v", def, err)
	}
}
