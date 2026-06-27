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

function rule_proto_txt(s) {
	const family = (uci.get('firewall', s, 'family') || '').toLowerCase().replace(/^(?:all|\*)$/, 'any');
	const sip = uci.get('firewall', s, 'src_ip') || '';
	const dip = uci.get('firewall', s, 'dest_ip') || '';
	const rwip = uci.get('firewall', s, 'snat_ip') || '';
	const ipv4 = (family == 'ipv4' || family == 'any' || (!family && sip.indexOf(':') == -1 && dip.indexOf(':') == -1 && rwip.indexOf(':') == -1));
	const ipv6 = (family == 'ipv6' || family == 'any' || (!family && (sip.indexOf(':') != -1 || dip.indexOf(':') != -1 || rwip.indexOf(':') != -1)));

	const proto = hybridtool.parseProto(uci.get('firewall', s, 'proto'));
	const f = hybridtool.parseMark(uci.get('firewall', s, 'mark'));

	const familyItems = [];
	const protoItems = [];
	const matchItems = [];

	if (ipv4 && ipv6) {
		familyItems.push(hybridtool.renderCapsule('Family', 'IPv4+IPv6'));
	} else if (ipv4) {
		familyItems.push(hybridtool.renderCapsule('Family', 'IPv4'));
	} else if (ipv6) {
		familyItems.push(hybridtool.renderCapsule('Family', 'IPv6'));
	}

	if (proto && proto.length) {
		proto.forEach(p => {
			protoItems.push(hybridtool.renderCapsule('Proto', p.name.toUpperCase()));
		});
	} else {
		protoItems.push(hybridtool.renderCapsule('Proto', _('Any')));
	}

	if (f) matchItems.push(hybridtool.renderMarkCapsule(f));

	const children = [];
	if (familyItems.length)
		children.push(hybridtool.renderGroup('family-group', familyItems));
	if (protoItems.length)
		children.push(hybridtool.renderGroup('proto-group', protoItems));
	if (matchItems.length)
		children.push(hybridtool.renderGroup('match-group', matchItems));

	if (!children.length)
		return E('em', { style: 'color:#999;' }, _('Any Protocol'));

	return E('div', { 'style': 'display:flex; flex-direction:column; gap:4px;' }, children);
}

function rule_src_txt(s, hosts) {
	const addrItems = [];

	const ips = fwtool.map_invert(uci.get('firewall', s, 'src_ip'), 'toLowerCase');
	if (ips && ips.length) {
		ips.forEach(ip => addrItems.push(hybridtool.renderCapsule('IP', ip.ival, ip.inv)));
	}

	const ports = fwtool.map_invert(uci.get('firewall', s, 'src_port'));
	if (ports && ports.length) {
		ports.forEach(p => addrItems.push(hybridtool.renderCapsule('Port', p.ival, p.inv)));
	}

	if (!addrItems.length)
		return E('em', { 'style': 'color:#999;' }, _('Any'));

	return hybridtool.renderGroup('addr-group', addrItems);
}

function rule_dest_txt(s) {
	const z = uci.get('firewall', s, 'src');
	const d = uci.get('firewall', s, 'device');

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

function rule_target_txt(sid) {
	const t = uci.get('firewall', sid, 'target');
	const snat_ip = uci.get('firewall', sid, 'snat_ip');
	const snat_port = uci.get('firewall', sid, 'snat_port');

	let style = '';
	let val = t;
	let details = '';

	if (t === 'SNAT') {
		style = 'background:rgba(23,162,184,0.15); color:#17a2b8; border-color:rgba(23,162,184,0.25);';
		val = _('SNAT');
		const items = [];
		if (snat_ip) items.push(snat_ip);
		if (snat_port) items.push(snat_port);
		details = items.join(':');
	} else if (t === 'MASQUERADE') {
		style = 'background:rgba(40,167,69,0.15); color:#28a745; border-color:rgba(40,167,69,0.25);';
		val = _('Masquerade');
	} else if (t === 'ACCEPT') {
		style = 'background:rgba(220,53,69,0.15); color:#dc3545; border-color:rgba(220,53,69,0.25);';
		val = _('Accept (No Rewrite)');
	}

	const displayVal = details ? '%s (%s)'.format(val, details) : val;

	return hybridtool.renderCapsule(_('Action'), displayVal, false, null, null, style);
}

function validate_opt_family(m, section_id, opt) {
	const sopt = m.section.getOption('src_ip');
	const dopt = m.section.getOption('dest_ip');
	const rwopt = m.section.getOption('snat_ip');
	const fmopt = m.section.getOption('family');
	const tgopt = m.section.getOption('target');

	if (!sopt.isValid(section_id) && opt != 'src_ip')
		return true;
	if (!dopt.isValid(section_id) && opt != 'dest_ip')
		return true;
	if (!rwopt.isValid(section_id) && opt != 'snat_ip')
		return true;
	if (!fmopt.isValid(section_id) && opt != 'family')
		return true;
	if (!tgopt.isValid(section_id) && opt != 'target')
		return true;

	const sip = sopt.formvalue(section_id) || '';
	const dip = dopt.formvalue(section_id) || '';
	const rwip = rwopt.formvalue(section_id) || '';
	const fm = fmopt.formvalue(section_id) || '';
	const tg = tgopt.formvalue(section_id);

	if (fm == 'ipv6' && (sip.indexOf(':') != -1 || sip == '') && (dip.indexOf(':') != -1 || dip == '') && ((rwip.indexOf(':') != -1 && tg == 'SNAT') || rwip == ''))
		return true;
	if (fm == 'ipv4' && (sip.indexOf(':') == -1) && (dip.indexOf(':') == -1) && ((rwip.indexOf(':') == -1 && tg == 'SNAT') || rwip == ''))
		return true;
	if (fm == '' || fm == 'any') {
		if ((sip.indexOf(':') != -1 || sip == '') && (dip.indexOf(':') != -1 || dip == '') && ((rwip.indexOf(':') != -1 && tg == 'SNAT') || rwip == ''))
			return true;
		if ((sip.indexOf(':') == -1) && (dip.indexOf(':') == -1) && ((rwip.indexOf(':') == -1 && tg == 'SNAT') || rwip == ''))
			return true;
	}

	return _('Address family, source address, destination address, rewrite IP address must match');
}

return view.extend({
	callHostHints: rpc.declare({
		object: 'luci-rpc',
		method: 'getHostHints',
		expect: { '': {} }
	}),

	callNetworkDevices: rpc.declare({
		object: 'luci-rpc',
		method: 'getNetworkDevices',
		expect: { '': {} }
	}),

	load() {
		return Promise.all([
			this.callHostHints(),
			this.callNetworkDevices(),
			uci.load('firewall')
		]);
	},

	render(data) {
		if (fwtool.checkLegacySNAT())
			return fwtool.renderMigration();
		else
			return this.renderNats(data);
	},

	renderNats([hosts, devs]) {
		const m = new form.Map('firewall', null, null);
		const fw4 = L.hasSystemFeature('firewall4');

		hybridtool.setupSaveHook(m, 'nat');

		const searchInput = hybridtool.createSearchInput(_('Live Filter (e.g. "wan", "192.168.1")...'));

		const zones = uci.sections('firewall', 'zone');
		zones.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

		const createSection = (title, filterFn, handleAddFn, isBlockHeader = false) => {
			const s = m.section(form.GridSection, 'nat', title);
			s.anonymous = true;
			s.addremove = true;
			s.sortable = true;
			s.cloneable = true;
			s.filterrow = true;

			s.filter = filterFn;
			s.handleAdd = handleAddFn;

			s.tab('general', _('General Settings'));
			s.tab('advanced', _('Advanced Settings'));
			s.tab('timed', _('Time Restrictions'));

			s.sectiontitle = function (section_id) {
				return uci.get('firewall', section_id, 'name') || _('Unnamed NAT');
			};

			const oName = s.taboption('general', form.Value, 'name', _('Name'));
			oName.placeholder = _('Unnamed NAT');
			oName.modalonly = true;

			if (fw4) {
				const oFamily = s.taboption('general', form.ListValue, 'family', _('Restrict to address family'));
				oFamily.modalonly = true;
				oFamily.rmempty = true;
				oFamily.value('any', _('IPv4 and IPv6'));
				oFamily.value('ipv4', _('IPv4 only'));
				oFamily.value('ipv6', _('IPv6 only'));
				oFamily.value('', _('automatic'));
				oFamily.cfgvalue = function (section_id) {
					const val = this.map.data.get(this.map.config, section_id, 'family');

					if (!val)
						return '';
					else if (val == 'any' || val == 'all' || val == '*')
						return 'any';
					else if (val == 'inet' || String(val).indexOf('4') != -1)
						return 'ipv4';
					else if (String(val).indexOf('6') != -1)
						return 'ipv6';
				};
				oFamily.validate = function (section_id, value) {
					fwtool.updateHostHints(this.map, section_id, 'src_ip', value, hosts);
					fwtool.updateHostHints(this.map, section_id, 'dest_ip', value, hosts);
					return !fw4 ? true : validate_opt_family(this, section_id, 'family');
				};
			}

			// Hybrid separated columns
			const oProto = s.option(form.DummyValue, '_proto', _('Protocol'));
			oProto.modalonly = false;
			oProto.textvalue = function (sid) {
				return rule_proto_txt(sid);
			};

			const oSrc = s.option(form.DummyValue, '_src', _('Source'));
			oSrc.modalonly = false;
			oSrc.textvalue = function (sid) {
				return rule_src_txt(sid, hosts);
			};

			const oDest = s.option(form.DummyValue, '_dest_capsules', _('Destination'));
			oDest.modalonly = false;
			oDest.textvalue = function (sid) {
				const dest = rule_dest_txt(sid);
				const limit = hybridtool.rule_limit_txt(sid);
				const ipset = uci.get('firewall', sid, 'ipset');

				const items = [];
				if (dest) items.push(E('div', { 'style': 'padding: 2px 0;' }, dest));
				if (ipset) items.push(E('div', { 'style': 'padding: 2px 0;' }, hybridtool.renderCapsule('IPSet', ipset)));
				if (limit) items.push(E('div', { 'style': 'padding: 2px 0;' }, limit));

				return E('div', { 'style': 'font-size: 0.95em;' }, items);
			};

			const oAction = s.option(form.DummyValue, '_action', _('Action'));
			oAction.modalonly = false;
			oAction.textvalue = function (sid) {
				const targetCapsule = rule_target_txt(sid);
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
			oEnabled.editable = true;

			let o;

			o = s.taboption('general', fwtool.CBIProtocolSelect, 'proto', _('Protocol'));
			o.modalonly = true;
			o.default = 'all';

			o = s.taboption('general', widgets.ZoneSelect, 'src', _('Outbound zone'));
			o.modalonly = true;
			o.rmempty = false;
			o.nocreate = true;
			o.allowany = true;
			o.default = 'lan';

			o = fwtool.addIPOption(s, 'general', 'src_ip', _('Source address'), _('Match forwarded traffic from this IP or range.'), !fw4 ? 'ipv4' : '', hosts);
			o = s.getOption ? s.getOption('src_ip') : null;
			if (o) {
				o.rmempty = true;
				o.datatype = !fw4 ? 'neg(ipmask4("true"))' : 'neg(ipmask("true"))';
				o.validate = function (section_id, value) {
					return !fw4 ? true : validate_opt_family(this, section_id, 'src_ip');
				};
			}

			o = s.taboption('general', form.Value, 'src_port', _('Source port'), _('Match forwarded traffic originating from the given source port or port range.'));
			o.modalonly = true;
			o.rmempty = true;
			o.datatype = 'neg(portrange)';
			o.placeholder = _('any');
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			fwtool.addIPOption(s, 'general', 'dest_ip', _('Destination address'), _('Match forwarded traffic directed at the given IP address.'), !fw4 ? 'ipv4' : '', hosts);
			o = s.getOption ? s.getOption('dest_ip') : null;
			if (o) {
				o.rmempty = true;
				o.datatype = !fw4 ? 'neg(ipmask4("true"))' : 'neg(ipmask("true"))';
				o.validate = function (section_id, value) {
					return !fw4 ? true : validate_opt_family(this, section_id, 'dest_ip');
				};
			}

			o = s.taboption('general', form.Value, 'dest_port', _('Destination port'), _('Match forwarded traffic directed at the given destination port or port range.'));
			o.modalonly = true;
			o.rmempty = true;
			o.placeholder = _('any');
			o.datatype = 'neg(portrange)';
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			o = s.taboption('general', form.ListValue, 'target', _('Action'));
			o.modalonly = true;
			o.default = 'SNAT';
			o.value('SNAT', _('SNAT - Rewrite to specific source IP or port'));
			o.value('MASQUERADE', _('MASQUERADE - Automatically rewrite to outbound interface IP'));
			o.value('ACCEPT', _('ACCEPT - Disable address rewriting'));
			o.validate = function (section_id, value) {
				return !fw4 ? true : validate_opt_family(this, section_id, 'target');
			};

			fwtool.addLocalIPOption(s, 'general', 'snat_ip', _('Rewrite IP address'), _('Rewrite matched traffic to the specified source IP address.'), devs);
			o = s.getOption ? s.getOption('snat_ip') : null;
			if (o) {
				o.placeholder = null;
				o.depends('target', 'SNAT');
				o.validate = function (section_id, value) {
					const a = this.formvalue(section_id);
					const p = this.section.formvalue(section_id, 'snat_port');

					if ((a == null || a == '') && (p == null || p == '') && value == '')
						return _('A rewrite IP must be specified!');

					return !fw4 ? true : validate_opt_family(this, section_id, 'snat_ip');
				};
			}

			o = s.taboption('general', form.Value, 'snat_port', _('Rewrite port'), _('Rewrite matched traffic to the specified source port or port range.'));
			o.modalonly = true;
			o.rmempty = true;
			o.placeholder = _('do not rewrite');
			o.datatype = 'portrange';
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			if (!fw4) {
				o = s.taboption('advanced', form.Value, 'ipset', _('Use ipset'));
				uci.sections('firewall', 'ipset', function (s_ipset) {
					if (typeof (s_ipset.name) == 'string')
						o.value(s_ipset.name, s_ipset.comment ? '%s (%s)'.format(s_ipset.name, s_ipset.comment) : s_ipset.name);
				});
				o.modalonly = true;
				o.rmempty = true;
			}

			o = s.taboption('advanced', widgets.DeviceSelect, 'device', _('Outbound device'), _('Matches forwarded traffic using the specified outbound network device.'));
			o.noaliases = true;
			o.modalonly = true;
			o.rmempty = true;

			fwtool.addMarkOption(s, false);
			fwtool.addLimitOption(s);
			fwtool.addLimitBurstOption(s);

			o = s.taboption('advanced', form.Flag, 'log', _('Enable logging'), _('Log matched packets to syslog.'));
			o.modalonly = true;

			if (!fw4) {
				o = s.taboption('advanced', form.Value, 'extra', _('Extra arguments'), _('Passes additional arguments to iptables. Use with care!'));
				o.modalonly = true;
				o.rmempty = true;
			}

			hybridtool.addTimeRestrictions(s);

			s.render = function () {
				return form.GridSection.prototype.render.apply(this, arguments).then(node => {
					return hybridtool.createSectionAccordion(title, node, isBlockHeader, this.cfgsections().length > 0);
				});
			};
		};

		// Block 1
		createSection(_('Global NAT Rules'), function (sid) {
			const s_src = uci.get('firewall', sid, 'src');
			return (s_src === undefined || s_src === '' || s_src === '*');
		}, function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'src', '*');
			uci.set(config_name, section_id, 'target', 'SNAT');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		}, true);

		// Block 2 Header
		const h2 = m.section(form.TypedSection, 'nat', _('Outbound Zone-specific NAT Rules'));
		h2.anonymous = true;
		h2.render = function () {
			return E('div', { 'style': 'margin-top: 1.5em; border-bottom: 2px solid #ccc; padding-bottom: 0.3em; display: flex; justify-content: space-between; align-items: center;' }, [
				E('h2', { 'style': 'margin: 0; font-size: 1.3em;' }, [this.title]),
				E('button', {
					'class': 'btn cbi-button-add',
					'click': ui.createHandlerFn(this, function (ev) {
						const select = E('select', { 'class': 'cbi-input-select' },
							zones.map(z => E('option', { 'value': z.name }, [z.name]))
						);

						ui.showModal(_('Add NAT Rule to Zone'), [
							E('p', _('Select the outbound zone for the new NAT rule:')),
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
										uci.set(config_name, section_id, 'target', 'SNAT');
										this.map.addedSection = section_id;

										const gridSec = this.map.children.find(s => s instanceof form.GridSection && s.filter(section_id));
										if (gridSec) {
											gridSec.renderMoreOptionsModal(section_id);
										}
									})
								}, [_('Add')])
							])
						]);
					})
				}, [_('Add NAT Rule to Zone')])
			]);
		};
		h2.filter = function () { return false; };

		// Block 2 Content
		zones.forEach(z => {
			const srcZone = z.name;
			const title = _('Outbound Zone: %s').format(srcZone);
			createSection(title, function (sid) {
				const s_src = uci.get('firewall', sid, 'src');
				return s_src === srcZone;
			}, function (ev) {
				const config_name = this.uciconfig || this.map.config;
				const section_id = uci.add(config_name, this.sectiontype);
				uci.set(config_name, section_id, 'src', srcZone);
				uci.set(config_name, section_id, 'target', 'SNAT');
				this.map.addedSection = section_id;
				this.renderMoreOptionsModal(section_id);
			});
		});

		return m.render().then(mapDom => {
			return E('div', { 'class': 'cbi-map' }, [
				E('h2', {}, [_('Firewall - NAT Rules (Hybrid)')]),
				E('div', { 'class': 'cbi-map-descr' }, [_('NAT rules allow fine grained control over the source IP to use for outbound or forwarded traffic. Blocks are collapsible.')]),
				searchInput,
				mapDom
			]);
		});
	}
});
