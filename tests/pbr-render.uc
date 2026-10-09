let render = require('pbr_render').render;
function check(ok, msg) { if (!ok) die(msg + '\n'); }
let uplinks = [ { network: 'telecom', device: 'pppoe-wan' },
	{ network: 'unicom', device: 'eth1' } ];
let cfg = { interfaces: [ { name: 'pppoe-wan' }, { name: 'eth1' } ],
	policy_skip_mark_mask: 0xff0000 };
let result = render(cfg, uplinks);
check(length(result.config.pbr_targets) == 3, 'balanced + two WAN targets');
check(result.config.pbr_targets[2].interface == 'eth1', 'live L3 mapping');
check(result.config.pbr_targets[1].mark == 0x100, 'stable first WAN mark');
check(result.config.pbr_targets[2].mark == 0x200, 'stable second WAN mark');
check(result.manifest.strategies.unicom_prefer == 'mwan4_strategy_unicom_prefer', 'consumer strategy API');
check(result.config.policy_skip_mark_mask == 0xff3f00, 'both PBR masks excluded');
check(index(result.nft, '0xffffc0ff') >= 0, 'preserve other mark bits');
check(index(result.nft, 'mwan4_strategy_balanced_ipv6 drop') >= 0, 'unsupported IPv6 fails closed');
// Keep the public target and mark stable even when netifd loses a WAN.
let offline = render({ interfaces: [ { name: 'pppoe-wan' } ] }, uplinks);
check(offline.config.pbr_targets[2].interface == null, 'offline WAN falls back to main');
check(offline.manifest.interfaces.unicom.mark == '0x200', 'offline WAN still discoverable');
// Device recreation must not change the public mark.
uplinks[1].device = 'pppoe-unicom';
let redial = render({ interfaces: [ { name: 'pppoe-unicom' } ] }, uplinks);
check(redial.config.pbr_targets[2].interface == 'pppoe-unicom', 'new PPPoE L3 device');
check(redial.config.pbr_targets[2].mark == 0x200, 'redial mark stable');
for (let bad in [ '', 'bad;name', 'wan-with-dash' ]) {
	let failed = false;
	try { render({ interfaces: [] }, [ { network: bad, device: '' } ]); }
	catch (e) { failed = true; }
	check(failed, 'invalid logical WAN name accepted');
}
let dup = false;
try { render({ interfaces: [] }, [uplinks[0], uplinks[0]]); } catch(e) { dup = true; }
check(dup, 'duplicate logical WAN accepted');
// Export a real nft batch for the privileged test (argv optional).
if (ARGV[0]) require('fs').writefile(ARGV[0], result.nft);
print('PASS: PBR renderer, stable marks, consumer targets and IPv6 guard\n');
