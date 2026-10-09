// MIT. Called only after explicit global.pbr_mode='mossdef'.
let fs = require('fs');
let ctx = require('uci').cursor();
let bus = require('ubus').connect();
let render = require('pbr_render').render;
if (ctx.get('pbr', 'config', 'enabled') != '1') die('Enable PBR before selecting mossdef mode\n');
if (ctx.get('pbr', 'config', 'ipv6_enabled') == '1')
	die('PBR strategy adapter currently supports IPv4 only; set pbr.config.ipv6_enabled=0\n');
if (!fs.stat('/lib/pbr/platform.uc')) die('PBR 1.2.3 consumer API is required for mossdef mode\n');
if (fs.stat('/usr/share/nftables.d/ruleset-post/20-pbr-netifd.nft'))
	die('Remove PBR netifd extensions before enabling the MWAN4 strategy adapter\n');
// PBR sizes its rule cleanup band from fw_mask/uplink_mark. A widened mask
// can delete other services' rules, even with disjoint mark bits.
require('pbr_render').validate_pbr_marks(ctx.get('pbr', 'config', 'fw_mask'),
	ctx.get('pbr', 'config', 'uplink_mark'));
let priority = int(ctx.get('pbr', 'config', 'uplink_ip_rules_priority') || '30000');
if (priority < 20000 || priority > 31000)
	die('PBR uplink_ip_rules_priority must be within 20000..31000\n');
let config = json(fs.readfile(ARGV[0]));
if ((config.policy_skip_mark_mask || 0) & 0x3f00)
	die('PBR fw_mask overlaps the adapter mask 0x3f00\n');
let uplinks = [];
ctx.foreach('mwan4', 'interface', function(section) {
	if (section.enabled == '0') return;
	if (!section.network) die('PBR strategy mode requires option network for each WAN\n');
	let status = bus.call('network.interface.' + section.network, 'status', {}) || {};
	push(uplinks, { network: section.network, device: status.l3_device || '' });
});
let result = render(config, uplinks);
for (let item in [ [ARGV[0], sprintf('%J\n', result.config)],
	[ARGV[1], sprintf('%J\n', result.manifest)], [ARGV[2], result.nft] ]) {
	if (fs.writefile(item[0], item[1]) != length(item[1])) die('Cannot write PBR adapter output\n');
}
