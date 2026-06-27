'use strict';
'require view';
'require ui';
'require rpc';
'require uci';
'require form';
'require dom';
'require tools.firewall as fwtool';
'require tools.widgets as widgets';
'require tools.firewall-hybrid as hybridtool';

function rule_proto_txt(s, ctHelpers) {
	const f = (uci.get('firewall', s, 'family') || '').toLowerCase().replace(/^(?:any|\*)$/, '');

	const proto = hybridtool.parseProto(uci.get('firewall', s, 'proto'), uci.get('firewall', s, 'icmp_type'));
	const h = hybridtool.parseHelper(uci.get('firewall', s, 'helper'), ctHelpers);
	const w = hybridtool.parseMark(uci.get('firewall', s, 'mark'));

	const m = String(uci.get('firewall', s, 'dscp')).match(/^(!\s*)?(?:(CS[0-7]|BE|AF[1234][123]|EF)|(0x[0-9a-f]{1,2}|[0-9]{1,2}))$/);
	const d = m ? {
		val: m[0],
		inv: m[1],
		name: m[2],
		num: m[3] ? '0x%02X'.format(+m[3]) : null
	} : null;

	const familyItems = [];
	const protoItems = [];
	const icmpItems = [];
	const matchItems = [];
	const helperItems = [];

	if (f && f !== 'any' && f !== '*') familyItems.push(hybridtool.renderCapsule('Family', f.toUpperCase()));

	if (proto && proto.length) {
		proto.forEach(p => {
			protoItems.push(hybridtool.renderCapsule('Proto', p.name.toUpperCase()));
			if (p.types && p.types.length) {
				p.types.forEach(t => icmpItems.push(hybridtool.renderCapsule('ICMP', t)));
			}
		});
	} else {
		protoItems.push(hybridtool.renderCapsule('Proto', _('Any')));
	}

	if (w) matchItems.push(hybridtool.renderMarkCapsule(w));
	if (d) matchItems.push(hybridtool.renderCapsule('DSCP', (d.inv ? '! ' : '') + d.val));
	if (h) helperItems.push(hybridtool.renderHelperCapsule(h));

	const children = [];
	if (familyItems.length)
		children.push(hybridtool.renderGroup('family-group', familyItems));
	if (protoItems.length)
		children.push(hybridtool.renderGroup('proto-group', protoItems));
	if (icmpItems.length)
		children.push(hybridtool.renderGroup('icmp-group', icmpItems));
	if (matchItems.length)
		children.push(hybridtool.renderGroup('match-group', matchItems));
	if (helperItems.length)
		children.push(hybridtool.renderGroup('helper-group', helperItems));

	if (!children.length)
		return E('em', { style: 'color:#999;' }, _('Any Protocol'));

	return E('div', { 'style': 'display:flex; flex-direction:column; gap:4px;' }, children);
}

function rule_src_txt(s, hosts) {
	const z = uci.get('firewall', s, 'src');
	const d = (uci.get('firewall', s, 'direction') == 'in') ? uci.get('firewall', s, 'device') : null;

	const baseItems = [];
	const addrItems = [];

	baseItems.push(hybridtool.renderZoneBadge(z));

	if (d) baseItems.push(hybridtool.renderCapsule('IF', d));

	const ips = fwtool.map_invert(uci.get('firewall', s, 'src_ip'), 'toLowerCase');
	if (ips && ips.length) {
		ips.forEach(ip => addrItems.push(hybridtool.renderCapsule('IP', ip.ival, ip.inv)));
	}

	const macs = fwtool.map_invert(uci.get('firewall', s, 'src_mac'), 'toUpperCase');
	if (macs && macs.length) {
		macs.forEach(mac => {
			const hint = hosts[mac.val] ? hosts[mac.val].name : null;
			addrItems.push(hybridtool.renderCapsule('MAC', mac.ival, mac.inv, hint));
		});
	}

	const ports = fwtool.map_invert(uci.get('firewall', s, 'src_port'));
	if (ports && ports.length) {
		ports.forEach(p => addrItems.push(hybridtool.renderCapsule('Port', p.ival, p.inv)));
	}

	const children = [];
	if (baseItems.length)
		children.push(hybridtool.renderGroup('base-group', baseItems, true));
	if (addrItems.length)
		children.push(hybridtool.renderGroup('addr-group', addrItems));

	return E('div', { 'style': 'display:flex; flex-direction:column; gap:4px;' }, children);
}

function rule_dest_txt(s) {
	const z = uci.get('firewall', s, 'dest');
	const d = (uci.get('firewall', s, 'direction') == 'out') ? uci.get('firewall', s, 'device') : null;

	const baseItems = [];
	const addrItems = [];

	baseItems.push(hybridtool.renderZoneBadge(z));

	if (d) baseItems.push(hybridtool.renderCapsule('IF', d));

	const ips = fwtool.map_invert(uci.get('firewall', s, 'dest_ip'), 'toLowerCase');
	if (ips && ips.length) {
		ips.forEach(ip => addrItems.push(hybridtool.renderCapsule('IP', ip.ival, ip.inv)));
	}

	const ports = fwtool.map_invert(uci.get('firewall', s, 'dest_port'));
	if (ports && ports.length) {
		ports.forEach(p => addrItems.push(hybridtool.renderCapsule('Port', p.ival, p.inv)));
	}

	const children = [];
	if (baseItems.length)
		children.push(hybridtool.renderGroup('base-group', baseItems, true));
	if (addrItems.length)
		children.push(hybridtool.renderGroup('addr-group', addrItems));

	return E('div', { 'style': 'display:flex; flex-direction:column; gap:4px;' }, children);
}

function rule_target_txt(sid, ctHelpers) {
	const t = uci.get('firewall', sid, 'target');
	const h = (uci.get('firewall', sid, 'set_helper') || '').toUpperCase();
	const helper_name = (ctHelpers.filter(function (ctH) { return ctH.name.toUpperCase() == h })[0] || {}).description;

	let style = '';
	let val = t;
	let details = '';

	if (t === 'ACCEPT') {
		style = 'background:rgba(40,167,69,0.15); color:#28a745; border-color:rgba(40,167,69,0.25);';
		val = _('Accept');
	} else if (t === 'DROP') {
		style = 'background:rgba(220,53,69,0.15); color:#dc3545; border-color:rgba(220,53,69,0.25);';
		val = _('Drop');
	} else if (t === 'REJECT') {
		style = 'background:rgba(220,53,69,0.15); color:#dc3545; border-color:rgba(220,53,69,0.25);';
		val = _('Reject');
	} else if (t === 'NOTRACK') {
		style = 'background:rgba(23,162,184,0.15); color:#17a2b8; border-color:rgba(23,162,184,0.25);';
		val = _("Don't track");
	} else if (t === 'HELPER') {
		style = 'background:rgba(23,162,184,0.15); color:#17a2b8; border-color:rgba(23,162,184,0.25);';
		val = _('Assign Helper');
		details = helper_name || h;
	} else if (t === 'MARK') {
		style = 'background:rgba(23,162,184,0.15); color:#17a2b8; border-color:rgba(23,162,184,0.25);';
		const set_mark = uci.get('firewall', sid, 'set_mark');
		const set_xmark = uci.get('firewall', sid, 'set_xmark');
		val = set_mark ? _('Assign Mark') : _('XOR Mark');
		details = set_mark || set_xmark;
	} else if (t === 'DSCP') {
		style = 'background:rgba(23,162,184,0.15); color:#17a2b8; border-color:rgba(23,162,184,0.25);';
		val = _('Assign DSCP');
		details = uci.get('firewall', sid, 'set_dscp');
	} else if (t) {
		val = t.charAt(0).toUpperCase() + t.slice(1).toLowerCase();
	} else {
		val = _('Unspecified');
	}

	const displayVal = details ? '%s (%s)'.format(val, details) : val;

	return hybridtool.renderCapsule(_('Action'), displayVal, false, null, null, style);
}


return view.extend({
	callHostHints: rpc.declare({
		object: 'luci-rpc',
		method: 'getHostHints',
		expect: { '': {} }
	}),

	callConntrackHelpers: rpc.declare({
		object: 'luci',
		method: 'getConntrackHelpers',
		expect: { result: [] }
	}),

	load() {
		return Promise.all([
			this.callHostHints(),
			this.callConntrackHelpers(),
			uci.load('firewall')
		]);
	},

	render(data) {
		if (fwtool.checkLegacySNAT())
			return fwtool.renderMigration();
		else
			return this.renderRules(data);
	},

	renderRules([hosts, ctHelpers]) {
		const m = new form.Map('firewall', null, null);

		hybridtool.setupSaveHook(m, 'rule');

		const searchInput = hybridtool.createSearchInput(_('Live Filter (e.g. "wan", "accept", "192.168.1")...'));

		const zones = uci.sections('firewall', 'zone');
		const zoneMap = {};
		zones.forEach(z => {
			zoneMap[z.name] = {
				input: (z.input || 'DROP').toUpperCase(),
				forward: (z.forward || 'DROP').toUpperCase()
			};
		});

		const defaults = uci.sections('firewall', 'defaults')[0] || {};
		const defInput = (defaults.input || 'DROP').toUpperCase();
		const defOutput = (defaults.output || 'ACCEPT').toUpperCase();

		zones.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

		const createSection = (title, filterFn, handleAddFn, isBlockHeader = false) => {
			const s = m.section(form.GridSection, 'rule', title);
			s.anonymous = true;
			s.addremove = true;
			s.sortable = true;
			s.cloneable = true;
			s.nodescription = true;

			s.filter = filterFn;
			s.handleAdd = handleAddFn;

			s.sectiontitle = function (section_id) {
				return uci.get('firewall', section_id, 'name') || _('Unnamed rule');
			};

			s.tab('general', _('General Settings'));
			s.tab('advanced', _('Advanced Settings'));
			s.tab('timed', _('Time Restrictions'));

			const oName = s.taboption('general', form.Value, 'name', _('Name'));
			oName.placeholder = _('Unnamed rule');
			oName.modalonly = true;

			const oProto = s.option(form.DummyValue, '_proto', _('Protocol'));
			oProto.modalonly = false;
			oProto.textvalue = function (sid) {
				const proto = rule_proto_txt(sid, ctHelpers);
				if (!proto) return '';
				return E('div', { 'style': 'font-size: 0.95em;' }, proto);
			};

			const oSrc = s.option(form.DummyValue, '_src', _('Source'));
			oSrc.modalonly = false;
			oSrc.textvalue = function (sid) {
				const src = rule_src_txt(sid, hosts);
				if (!src) return '';
				return E('div', { 'style': 'font-size: 0.95em;' }, src);
			};

			const oDest = s.option(form.DummyValue, '_dest', _('Destination'));
			oDest.modalonly = false;
			oDest.textvalue = function (sid) {
				const dest = rule_dest_txt(sid);
				const limit = hybridtool.rule_limit_txt(sid, 'text');
				const ipset = uci.get('firewall', sid, 'ipset');

				const items = [];
				if (dest) items.push(E('div', { 'style': 'padding: 2px 0;' }, dest));
				if (ipset) items.push(hybridtool.renderCapsule('IPSet', ipset));
				if (limit) items.push(E('div', { 'style': 'padding: 2px 0;' }, limit));

				if (items.length === 0) return '';
				return E('div', { 'style': 'font-size: 0.95em;' }, items);
			};

			const oTarget = s.option(form.ListValue, '_target', _('Action'));
			oTarget.modalonly = false;
			oTarget.textvalue = function (sid) {
				const targetCapsule = rule_target_txt(sid, ctHelpers);
				const timeCapsule = hybridtool.rule_time_txt(sid);
				if (timeCapsule) {
					return E('div', { 'style': 'display:flex; flex-direction:column; gap:4px; align-items:flex-start;' }, [
						targetCapsule,
						timeCapsule
					]);
				}
				return targetCapsule;
			};

			const oEnabled = s.option(form.Flag, 'enabled', _('Enable'));
			oEnabled.modalonly = false;
			oEnabled.default = oEnabled.enabled;
			oEnabled.rmempty = false;
			oEnabled.editable = true;

			let o;

			o = s.taboption('advanced', form.ListValue, 'direction', _('Match device'));
			o.modalonly = true;
			o.value('', _('unspecified'));
			o.value('in', _('Inbound device'));
			o.value('out', _('Outbound device'));
			o.cfgvalue = function (section_id) {
				const val = uci.get('firewall', section_id, 'direction');
				switch (val) {
					case 'in':
					case 'ingress':
						return 'in';
					case 'out':
					case 'egress':
						return 'out';
				}
				return null;
			};

			o = s.taboption('advanced', widgets.DeviceSelect, 'device', _('Device name'),
				_('Specifies whether to tie this traffic rule to a specific inbound or outbound network device.'));
			o.modalonly = true;
			o.noaliases = true;
			o.rmempty = false;
			o.depends('direction', 'in');
			o.depends('direction', 'out');

			o = s.taboption('advanced', form.ListValue, 'family', _('Restrict to address family'));
			o.modalonly = true;
			o.rmempty = true;
			o.value('', _('IPv4 and IPv6'));
			o.value('ipv4', _('IPv4 only'));
			o.value('ipv6', _('IPv6 only'));
			o.validate = function (section_id, value) {
				fwtool.updateHostHints(this.map, section_id, 'src_ip', value, hosts);
				fwtool.updateHostHints(this.map, section_id, 'dest_ip', value, hosts);
				return true;
			};

			o = s.taboption('general', fwtool.CBIProtocolSelect, 'proto', _('Protocol'));
			o.modalonly = true;
			o.default = 'tcp udp';

			o = s.taboption('advanced', form.MultiValue, 'icmp_type', _('Match ICMP type'));
			o.modalonly = true;
			o.multiple = true;
			o.custom = true;
			o.cast = 'table';
			o.placeholder = _('any/all');
			o.value('address-mask-reply');
			o.value('address-mask-request');
			o.value('address-unreachable'); /* icmpv6 1:3 */
			o.value('bad-header');  /* icmpv6 4:0 */
			o.value('certification-path-solicitation-message'); /* icmpv6 148 */
			o.value('certification-path-advertisement-message'); /* icmpv6 149 */
			o.value('communication-prohibited');
			o.value('destination-unreachable');
			o.value('duplicate-address-request'); /* icmpv6 157 */
			o.value('duplicate-address-confirmation'); /* icmpv6 158 */
			o.value('echo-reply');
			o.value('echo-request');
			o.value('extended-echo-request'); /* icmpv6 160 */
			o.value('extended-echo-reply'); /* icmpv6 161 */
			o.value('fmipv6-message'); /* icmpv6 154 */
			o.value('fragmentation-needed');
			o.value('home-agent-address-discovery-reply-message'); /* icmpv6 145 */
			o.value('home-agent-address-discovery-request-message'); /* icmpv6 144 */
			o.value('host-precedence-violation');
			o.value('host-prohibited');
			o.value('host-redirect');
			o.value('host-unknown');
			o.value('host-unreachable');
			o.value('ilnpv6-locator-update-message'); /* icmpv6 156 */
			o.value('inverse-neighbour-discovery-advertisement-message'); /* icmpv6 142 */
			o.value('inverse-neighbour-discovery-solicitation-message'); /* icmpv6 141 */
			o.value('ip-header-bad');
			o.value('mobile-prefix-advertisement'); /* icmpv6 147 */
			o.value('mobile-prefix-solicitation'); /* icmpv6 146 */
			o.value('mpl-control-message'); /* icmpv6 159 */
			o.value('multicast-listener-query'); /* icmpv6 130 */
			o.value('multicast-listener-report'); /* icmpv6 131 */
			o.value('multicast-listener-done'); /* icmpv6 132 */
			o.value('multicast-router-advertisement'); /* icmpv6 151 */
			o.value('multicast-router-solicitation'); /* icmpv6 152 */
			o.value('multicast-router-termination'); /* icmpv6 153 */
			o.value('neighbour-advertisement');
			o.value('neighbour-solicitation');
			o.value('network-prohibited');
			o.value('network-redirect');
			o.value('network-unknown');
			o.value('network-unreachable');
			o.value('no-route'); /* icmpv6 1:0 */
			o.value('node-info-query'); /* icmpv6 139 */
			o.value('node-info-response'); /* icmpv6 140 */
			o.value('packet-too-big');
			o.value('parameter-problem');
			o.value('port-unreachable');
			o.value('precedence-cutoff');
			o.value('protocol-unreachable');
			o.value('redirect');
			o.value('required-option-missing');
			o.value('router-advertisement');
			o.value('router-renumbering'); /* icmpv6 138 */
			o.value('router-solicitation');
			o.value('rpl-control-message'); /* icmpv6 155 */
			o.value('source-quench');
			o.value('source-route-failed');
			o.value('time-exceeded');
			o.value('timestamp-reply');
			o.value('timestamp-request');
			o.value('TOS-host-redirect');
			o.value('TOS-host-unreachable');
			o.value('TOS-network-redirect');
			o.value('TOS-network-unreachable');
			o.value('ttl-zero-during-reassembly');
			o.value('ttl-zero-during-transit');
			o.value('v2-multicast-listener-report'); /* icmpv6 143 */
			o.value('unknown-header-type'); /* icmpv6 4:1 */
			o.value('unknown-option'); /* icmpv6 4:2 */
			o.depends({ proto: 'icmp', '!contains': true });
			o.depends({ proto: 'icmpv6', '!contains': true });

			o = s.taboption('general', widgets.ZoneSelect, 'src', _('Source zone'));
			o.modalonly = true;
			o.nocreate = true;
			o.allowany = true;
			o.allowlocal = 'src';

			o = s.taboption('advanced', form.Value, 'ipset', _('Use ipset'));
			uci.sections('firewall', 'ipset', function (s_ipset) {
				if (typeof (s_ipset.name) == 'string')
					o.value(s_ipset.name, s_ipset.comment ? '%s (%s)'.format(s_ipset.name, s_ipset.comment) : s_ipset.name);
			});
			o.modalonly = true;
			o.rmempty = true;

			fwtool.addMACOption(s, 'advanced', 'src_mac', _('Source MAC address'), null, hosts);
			fwtool.addIPOption(s, 'general', 'src_ip', _('Source address'), null, '', hosts, true);

			o = s.taboption('general', form.Value, 'src_port', _('Source port'));
			o.modalonly = true;
			o.datatype = 'list(neg(portrange))';
			o.placeholder = _('any');
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			o = s.taboption('general', widgets.ZoneSelect, 'dest', _('Destination zone'));
			o.modalonly = true;
			o.nocreate = true;
			o.allowany = true;
			o.allowlocal = true;

			fwtool.addIPOption(s, 'general', 'dest_ip', _('Destination address'), null, '', hosts, true);

			o = s.taboption('general', form.Value, 'dest_port', _('Destination port'));
			o.modalonly = true;
			o.datatype = 'list(neg(portrange))';
			o.placeholder = _('any');
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			o = s.taboption('general', form.ListValue, 'target', _('Action'));
			o.modalonly = true;
			o.default = 'ACCEPT';
			o.rmempty = false;
			o.value('DROP', _('drop'));
			o.value('ACCEPT', _('accept'));
			o.value('REJECT', _('reject'));
			o.value('NOTRACK', _("don't track"));
			o.value('HELPER', _('assign conntrack helper'));
			o.value('MARK_SET', _('apply firewall mark'));
			o.value('MARK_XOR', _('XOR firewall mark'));
			o.value('DSCP', _('DSCP classification'));
			o.cfgvalue = function (section_id) {
				const t = uci.get('firewall', section_id, 'target');
				const m = uci.get('firewall', section_id, 'set_mark');
				if (t == 'MARK') return m ? 'MARK_SET' : 'MARK_XOR';
				return t;
			};
			o.write = function (section_id, value) {
				return this.super('write', [section_id, (value == 'MARK_SET' || value == 'MARK_XOR') ? 'MARK' : value]);
			};

			o = s.taboption('general', form.ListValue, 'set_helper', _('Tracking helper'), _('Assign the specified connection tracking helper to matched traffic.'));
			o.modalonly = true;
			o.placeholder = _('any');
			o.depends('target', 'HELPER');
			for (let cth of ctHelpers)
				o.value(cth.name, '%s (%s)'.format(cth.description, cth.name.toUpperCase()));

			o = s.taboption('advanced', form.Value, 'helper', _('Match helper'), _('Match traffic using the specified connection tracking helper.'));
			o.modalonly = true;
			o.placeholder = _('any');
			for (let cth of ctHelpers)
				o.value(cth.name, '%s (%s)'.format(cth.description, cth.name.toUpperCase()));
			o.validate = function (section_id, value) {
				if (value == '' || value == null)
					return true;
				value = value.replace(/^!\s*/, '');
				for (let cth of ctHelpers)
					if (value == cth.name)
						return true;
				return _('Unknown or not installed conntrack helper "%s"').format(value);
			};

			fwtool.addMarkOption(s, 1);
			fwtool.addMarkOption(s, 2);
			fwtool.addDSCPOption(s, true);

			fwtool.addMarkOption(s, false);
			fwtool.addDSCPOption(s, false);
			fwtool.addLimitOption(s);
			fwtool.addLimitBurstOption(s);

			o = s.taboption('advanced', form.Flag, 'log', _('Enable logging'), _('Log matched packets to syslog.'));
			o.modalonly = true;

			o = s.taboption('advanced', form.Value, 'log_limit', _('Limit log messages'));
			o.depends('log', '1');
			o.placeholder = '10/minute';
			o.modalonly = true;

			if (!L.hasSystemFeature('firewall4')) {
				o = s.taboption('advanced', form.Value, 'extra', _('Extra arguments'),
					_('Passes additional arguments to iptables. Use with care!'));
				o.modalonly = true;
			}

			o = s.taboption('advanced', form.ListValue, '_hybrid_block', _('Global Rule Position'), _('Determines if this global rule evaluates before or after zone rules.'));
			o.value('', _('PRE-Global (Evaluates Top)'));
			o.value('post', _('POST-Global (Evaluates Bottom)'));
			o.modalonly = true;
			o.depends({ src: '*', dest: /.+/ });

			hybridtool.addTimeRestrictions(s);

			s.render = function () {
				return form.GridSection.prototype.render.apply(this, arguments).then(node => {
					return hybridtool.createSectionAccordion(title, node, isBlockHeader, this.cfgsections().length > 0);
				});
			};
		};

		// Block 1
		createSection(_('Device Management (Input: %s / Output: %s)').format(defInput, defOutput), function (sid) {
			const s_src = uci.get('firewall', sid, 'src');
			const s_dest = uci.get('firewall', sid, 'dest');
			const p_src = (s_src === undefined || s_src === '') ? '' : s_src;
			const p_dest = (s_dest === undefined || s_dest === '') ? '' : s_dest;
			return (p_src === '' || p_dest === '') && uci.get('firewall', sid, 'target') != 'SNAT';
		}, function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'src', '*');
			uci.set(config_name, section_id, 'dest', '');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		}, true);

		// Block 2
		createSection(_('Global Pre-Rules'), function (sid) {
			const s_src = uci.get('firewall', sid, 'src');
			const s_dest = uci.get('firewall', sid, 'dest');
			const p_src = (s_src === undefined || s_src === '') ? '' : s_src;
			const p_dest = (s_dest === undefined || s_dest === '') ? '' : s_dest;
			const hb = uci.get('firewall', sid, '_hybrid_block');
			return p_src === '*' && p_dest !== '' && hb !== 'post' && uci.get('firewall', sid, 'target') != 'SNAT';
		}, function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'src', '*');
			uci.set(config_name, section_id, 'dest', '*');
			uci.set(config_name, section_id, '_hybrid_block', '');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		}, true);

		// Block 3 Header
		const h3 = m.section(form.TypedSection, 'rule', _('Zone-specific Forwarding Rules'));
		h3.anonymous = true;
		h3.render = function () {
			return E('div', { 'style': 'margin-top: 1.5em; border-bottom: 2px solid #ccc; padding-bottom: 0.3em; display: flex; justify-content: space-between; align-items: center;' }, [
				E('h3', { 'style': 'margin: 0;' }, [this.title]),
				E('button', {
					'class': 'btn cbi-button-add',
					'click': ui.createHandlerFn(this, function (ev) {
						const select = E('select', { 'class': 'cbi-input-select' },
							zones.map(z => E('option', { 'value': z.name }, [z.name]))
						);

						ui.showModal(_('Add Rule to Zone'), [
							E('p', _('Select the source zone for the new rule:')),
							E('div', { 'style': 'margin: 1em 0;' }, [select]),
							E('div', { 'class': 'right' }, [
								E('button', {
									'class': 'btn cbi-button-neutral',
									'style': 'margin-right: 0.5em;',
									'click': function () { ui.hideModal(); }
								}, [_('Cancel')]),
								E('button', {
									'class': 'btn cbi-button-action important',
									'click': ui.createHandlerFn(this, function () {
										const chosenZone = select.value;
										ui.hideModal();
										if (!chosenZone) return;

										const config_name = this.uciconfig || this.map.config;
										const section_id = uci.add(config_name, this.sectiontype);
										uci.set(config_name, section_id, 'src', chosenZone);
										uci.set(config_name, section_id, 'dest', '*');
										this.map.addedSection = section_id;

										const gridSec = this.map.children.find(s => s instanceof form.GridSection);
										if (gridSec) {
											gridSec.renderMoreOptionsModal(section_id);
										}
									})
								}, [_('Add')])
							])
						]);
					})
				}, [_('Add Zone Policy Rule')])
			]);
		};
		h3.filter = function () { return false; }; // Don't match any UCI sections

		// Block 3 Content
		zones.forEach(z => {
			const srcZone = z.name;
			const zp = zoneMap[srcZone] || { input: 'REJECT', forward: 'REJECT' };
			const title = _('Source Zone: %s [Input: %s] [Forward: %s]').format(srcZone, zp.input, zp.forward);
			createSection(title, function (sid) {
				const s_src = uci.get('firewall', sid, 'src');
				const s_dest = uci.get('firewall', sid, 'dest');
				const p_src = (s_src === undefined || s_src === '') ? '' : s_src;
				const p_dest = (s_dest === undefined || s_dest === '') ? '' : s_dest;
				return p_src === srcZone && p_dest !== '' && uci.get('firewall', sid, 'target') != 'SNAT';
			}, function (ev) {
				const config_name = this.uciconfig || this.map.config;
				const section_id = uci.add(config_name, this.sectiontype);
				uci.set(config_name, section_id, 'src', srcZone);
				uci.set(config_name, section_id, 'dest', '*');
				this.map.addedSection = section_id;
				this.renderMoreOptionsModal(section_id);
			});
		});

		// Block 4 Header
		const h4 = m.section(form.TypedSection, 'rule', _('Global Post-Rules'));
		h4.anonymous = true;
		h4.render = function () {
			return E('h3', { 'style': 'margin-top: 2em; border-bottom: 2px solid #ccc; padding-bottom: 0.3em;' }, [this.title]);
		};
		h4.filter = function () { return false; };

		// Block 4
		createSection(_('Global Post-Rules (Bottom of Forward Chain)'), function (sid) {
			const s_src = uci.get('firewall', sid, 'src');
			const s_dest = uci.get('firewall', sid, 'dest');
			const p_src = (s_src === undefined || s_src === '') ? '' : s_src;
			const p_dest = (s_dest === undefined || s_dest === '') ? '' : s_dest;
			const hb = uci.get('firewall', sid, '_hybrid_block');
			return p_src === '*' && p_dest !== '' && hb === 'post' && uci.get('firewall', sid, 'target') != 'SNAT';
		}, function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'src', '*');
			uci.set(config_name, section_id, 'dest', '*');
			uci.set(config_name, section_id, '_hybrid_block', 'post');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		}, true);

		return m.render().then(mapDom => {
			return E('div', { 'class': 'cbi-map' }, [
				E('h2', {}, [_('Traffic Rules (Hybrid View)')]),
				E('div', { 'class': 'cbi-map-descr' }, [_('Grouped by source zone. Blocks are collapsible.')]),
				searchInput,
				mapDom
			]);
		});
	}
});
