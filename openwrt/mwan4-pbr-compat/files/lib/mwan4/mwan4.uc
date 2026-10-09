// MIT. Consumer API compatible with mossdef PBR 1.2.3.
// No nft, route, UCI or service mutations occur when PBR imports this module.
let data = { interfaces: {}, strategies: {} };
function load() {
	data = { interfaces: {}, strategies: {} };
	let ctx = require('uci').cursor();
	if (ctx.get('mwan4', 'global', 'enabled') != '1' ||
		ctx.get('mwan4', 'global', 'pbr_mode') != 'mossdef') return;
	let raw = require('fs').readfile('/var/etc/mwan4-pbr.json');
	if (raw) data = json(raw);
}
return {
	load: load,
	get_interfaces: function() { return keys(data.interfaces); },
	get_iface_mark: function(iface) { return data.interfaces[iface]?.mark; },
	get_iface_chain: function(iface) { return data.interfaces[iface]?.chain; },
	get_strategies: function() { return keys(data.strategies); },
	get_strategy_chain: function(strategy) { return data.strategies[strategy]; },
	pkg: { NFT_FILES: { runtime: '/usr/share/nftables.d/ruleset-post/25-mwan4-pbr.nft' } },
};
