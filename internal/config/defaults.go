package config

// DefaultGroups returns independent policy containers for the initial device types.
func DefaultGroups() map[string]Policy {
	return map[string]Policy{
		"infrastructure": {},
		"mobile":         {},
		"iot":            {},
		"trusted":        {},
		"other":          {},
	}
}

// DefaultSubscriptions mirrors the AdGuard Home v1.0.0 first-run selection.
func DefaultSubscriptions() map[string]Subscription {
	const registry = "https://adguardteam.github.io/HostlistsRegistry/assets/"
	return map[string]Subscription{
		"adguard-filters-1": {Name: "AdGuard DNS filter", Format: AdGuardFormat, URL: registry + "filter_1.txt", Enabled: true},
		"adguard-filters-2": {Name: "AdAway Default Blocklist", Format: AdGuardFormat, URL: registry + "filter_2.txt"},
	}
}

func Defaults() Desired {
	return Desired{Version: Version, Default: Policy{Mode: Filtered}, DynamicTTL: 60, StaticTTL: 300,
		Groups: DefaultGroups(), Subscriptions: DefaultSubscriptions()}
}
