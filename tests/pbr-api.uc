let mode = 'mossdef', enabled = '1';
// Supply the two consumer dependencies without any router service mutations.
modules.uci = { cursor: function() { return {
	get: function(pkg, section, key) { return key == 'enabled' ? enabled : mode; }
}; } };
modules.fs = { readfile: function(path) {
	if (path != '/var/etc/mwan4-pbr.json') die('Unexpected manifest path\n');
	return '{"interfaces":{"wan":{"mark":"0x100","chain":"mwan4_iface_in_1"}},"strategies":{"balanced":"mwan4_strategy_balanced"}}';
} };
let api = require('mwan4');
function check(ok) { if (!ok) die('PBR consumer API regression\n'); }
api.load();
check(api.get_interfaces()[0] == 'wan');
check(api.get_iface_mark('wan') == '0x100');
check(api.get_iface_chain('wan') == 'mwan4_iface_in_1');
check(api.get_strategies()[0] == 'balanced');
check(api.get_strategy_chain('balanced') == 'mwan4_strategy_balanced');
mode = 'standalone';
api.load();
check(length(api.get_interfaces()) == 0 && length(api.get_strategies()) == 0);
mode = 'mossdef'; enabled = '0';
api.load();
check(length(api.get_strategies()) == 0);
print('PASS: PBR 1.2.3 consumer API and opt-in/disabled isolation\n');
