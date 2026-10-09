// MIT. Rust ECMP adapter: PBR matches packets, Rust owns routing and health.
// Pure renderer shared by the router entry point and host regression tests.
function render(config, uplinks) {
	if (length(uplinks) > 62)
		die('PBR strategy mode supports at most 62 logical WAN interfaces\n');
	let mask = 0x3f00;
	let interfaces = {}, strategies = {}, targets = [], lines = [];
	function chain(prefix, mark) {
		let name = prefix + '_ipv4';
		push(lines, 'add chain inet fw4 ' + name);
		push(lines, 'flush chain inet fw4 ' + name);
		push(lines, sprintf('add rule inet fw4 %s meta mark set (meta mark & 0xffffc0ff) | 0x%x', name, mark));
		// Unsupported IPv6 policy matching fails closed. Ordinary IPv6 traffic
		// never enters these chains; integrated mode requires ipv6_enabled=0.
		push(lines, 'add chain inet fw4 ' + prefix + '_ipv6');
		push(lines, 'flush chain inet fw4 ' + prefix + '_ipv6');
		push(lines, 'add rule inet fw4 ' + prefix + '_ipv6 drop');
	}
	strategies.balanced = 'mwan4_strategy_balanced';
	push(targets, { name: 'balanced', mark: mask, interface: null });
	chain('mwan4_strategy_balanced', mask);
	for (let i = 0; i < length(uplinks); i++) {
		let uplink = uplinks[i];
		if (!match(uplink.network || '', /^[A-Za-z0-9_]+$/) || length(uplink.network) > 48)
			die('PBR adapter needs a logical WAN name of 1..48 letters, digits or underscores\n');
		if (interfaces[uplink.network]) die('Duplicate PBR logical WAN: ' + uplink.network + '\n');
		let mark = (i + 1) << 8;
		let iface = null;
		for (let candidate in config.interfaces)
			if (candidate.name == uplink.device) iface = candidate.name;
		let prefix = 'mwan4_iface_in_' + (i + 1);
		interfaces[uplink.network] = { mark: sprintf('0x%x', mark), chain: prefix };
		let strategy = uplink.network + '_prefer';
		strategies[strategy] = 'mwan4_strategy_' + strategy;
		push(targets, { name: uplink.network, mark: mark, interface: iface });
		chain(prefix, mark);
		chain(strategies[strategy], mark);
	}
	config.pbr_targets = targets;
	config.policy_skip_mark_mask = (config.policy_skip_mark_mask || 0) | mask;
	return { config: config, manifest: { interfaces: interfaces, strategies: strategies },
		nft: join('\n', lines) + '\n' };
}
return { render: render };
