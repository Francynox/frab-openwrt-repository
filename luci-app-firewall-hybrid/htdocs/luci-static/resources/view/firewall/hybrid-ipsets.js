'use strict';
/* global hybridtool */
'require view';
'require uci';
'require form';
'require firewall';
'require tools.firewall as fwtool';
'require tools.firewall-hybrid as hybridtool';


function ipset_details_txt(sid, have_fw4) {
	const items = [];

	if (have_fw4) {
		const entries = L.toArray(uci.get('firewall', sid, 'entry'));
		if (entries.length > 0) {
			entries.forEach(e => {
				items.push(hybridtool.renderCapsule('Entry', e));
			});
		}
	} else {
		const ext = uci.get('firewall', sid, 'external');
		if (ext) {
			items.push(hybridtool.renderCapsule('External Set', ext));
		} else {
			const storage = uci.get('firewall', sid, 'storage');
			if (storage) {
				items.push(hybridtool.renderCapsule('Storage', storage));
			}
			const iprange = uci.get('firewall', sid, 'iprange');
			if (iprange) {
				items.push(hybridtool.renderCapsule('IP Range', iprange));
			}
			const entries = L.toArray(uci.get('firewall', sid, 'entry'));
			if (entries.length > 0) {
				entries.forEach(e => {
					items.push(hybridtool.renderCapsule('Entry', e));
				});
			}
			const portrange = uci.get('firewall', sid, 'portrange');
			if (portrange) {
				items.push(hybridtool.renderCapsule('Port Range', portrange));
			}
			const netmask = uci.get('firewall', sid, 'netmask');
			if (netmask) {
				items.push(hybridtool.renderCapsule('Netmask', netmask));
			}
		}
	}

	const loadfile = uci.get('firewall', sid, 'loadfile');
	if (loadfile) {
		items.push(hybridtool.renderCapsule('File', loadfile));
	}

	const maxelem = uci.get('firewall', sid, 'maxelem');
	if (maxelem) {
		items.push(hybridtool.renderCapsule('Max Elem', maxelem));
	}

	const hashsize = uci.get('firewall', sid, 'hashsize');
	if (hashsize) {
		items.push(hybridtool.renderCapsule('Hash Size', hashsize));
	}

	const timeout = uci.get('firewall', sid, 'timeout');
	if (timeout && timeout !== '0') {
		items.push(hybridtool.renderCapsule('Timeout', timeout + 's'));
	}

	const counters = uci.get('firewall', sid, 'counters') === '1';
	if (counters) {
		items.push(hybridtool.renderCapsule('Counters', _('Enabled')));
	}

	if (items.length === 0) {
		return E('em', { 'style': 'color:#999;' }, _('No entries'));
	}

	return E('div', { 'style': 'display:flex; flex-flow:row wrap; gap:4px;' }, items);
}


return view.extend({

	load() {
		return Promise.all([
			uci.load('firewall')
		]);
	},

	render() {
		const m = new form.Map('firewall', null, null);
		const have_fw4 = L.hasSystemFeature('firewall4');

		hybridtool.setupSaveHook(m, 'ipset');

		const searchInput = hybridtool.createSearchInput(_('Live Filter (e.g. "ipv4", "hash", "name")...'));

		const createSection = (title, filterFn, handleAddFn, isBlockHeader = false) => {
			const s = m.section(form.GridSection, 'ipset', title);
			s.addremove = true;
			s.anonymous = true;
			s.sortable = true;
			s.cloneable = true;
			s.nodescriptions = true;

			s.filter = filterFn;
			s.handleAdd = handleAddFn;

			s.sectiontitle = function (section_id) {
				return uci.get('firewall', section_id, 'name') || _('Unnamed set');
			};

			/* refer to: https://ipset.netfilter.org/ipset.man.html */
			let o;
			if (have_fw4) {
				o = s.option(form.Value, 'name', _('Name'));
				o.optional = false;
				o.rmempty = false;
				o.validate = function (section_id, value) {
					if (!/^[a-zA-Z_.][a-zA-Z0-9/_.-]*$/.test(value))
						return _('Invalid set name');

					return true;
				};
			} else {
				o = s.option(form.Value, 'name', _('Name'));
				o.depends({ external: '' });
			}
			o.placeholder = _('Unnamed set');
			o.modalonly = true;

			/* comment requires https://git.openwrt.org/?p=project/firewall4.git;a=commitdiff;h=39e8c70957c795bf0c12f04299170ae86c6efdf8 */
			o = s.option(form.Value, 'comment', _('Comment'));
			o.placeholder = _('Comment');
			o.modalonly = true;
			o.rmempty = true;

			o = s.option(form.ListValue, 'family', _('Family'));
			o.value('any', _('IPv4 and IPv6'));
			o.value('ipv4', _('IPv4'));
			o.value('ipv6', _('IPv6'));
			o.default = 'ipv4';
			o.modalonly = true;

			/* Direction src, dst; (Data)Types: ip, port, mac, net or set
			   Tuples: direction_datatype e.g. src_port, dest_net */
			o = s.option(form.DynamicList, 'match', _('Packet Field Match'),
				_('Packet fields to match upon.<br />' +
					'Syntax: <em>direction_datatype</em>. e.g.: <code>src_port, dest_net</code>.<br />' +
					'Directions: <code>src, dst</code>. Datatypes: <code>ip, port, mac, net, set</code>.<br />' +
					'Direction prefixes are optional.<br />' +
					'*Note: datatype <code>set</code> is unsupported in fw4.'));
			o.value('ip', _('ip: IP addr'));
			o.value('port', _('port: Port'));
			o.value('mac', _('mac: MAC addr'));
			o.value('net', _('net: (sub)net'));
			if (!have_fw4)
				o.value('set', _('set: ipset*'));
			o.value('src_ip', _('src_ip: Source IP'));
			o.value('src_port', _('src_port: Source Port'));
			o.value('src_mac', _('src_mac: Source MAC addr'));
			o.value('src_net', _('src_net: Source (sub)net'));
			if (!have_fw4)
				o.value('src_set', _('src_Set: Source ipset*')); // fw4 unsupported
			o.value('dest_ip', _('dest_ip: Destination IP'));
			o.value('dest_port', _('dest_port: Destination Port'));
			o.value('dest_mac', _('dest_mac: Destination MAC addr'));
			o.value('dest_net', _('dest_net: Destination (sub)net'));
			if (!have_fw4)
				o.value('dest_set', _('dest_set: Destination ipset*')); // fw4 unsupported
			o.optional = false;
			o.rmempty = false;
			o.modalonly = true;

			// Dummy capsule columns
			const oFamily = s.option(form.DummyValue, '_family', _('Family'));
			oFamily.modalonly = false;
			oFamily.textvalue = function (sid) {
				const f = uci.get('firewall', sid, 'family') || 'ipv4';
				let label = '';
				if (f === 'ipv4') label = 'IPv4';
				else if (f === 'ipv6') label = 'IPv6';
				else if (f === 'any') label = 'IPv4+IPv6';
				return hybridtool.renderCapsule('Family', label);
			};

			const oMatch = s.option(form.DummyValue, '_match', _('Packet Field Match'));
			oMatch.modalonly = false;
			oMatch.textvalue = function (sid) {
				const mVal = L.toArray(uci.get('firewall', sid, 'match'));
				if (!mVal.length) return E('em', { 'style': 'color:#999;' }, _('None'));
				const items = mVal.map(val => hybridtool.renderCapsule('Match', val));
				return E('div', { 'style': 'display:flex; flex-flow:row wrap; gap:4px;' }, items);
			};

			const oDetails = s.option(form.DummyValue, '_details', _('Details'));
			oDetails.modalonly = false;
			oDetails.textvalue = function (sid) {
				return ipset_details_txt(sid, have_fw4);
			};

			// TODO: if/when firewall5 arrives, this 'else' check must change.
			if (have_fw4) {
				//we have fw4
				o = s.option(form.DynamicList, 'entry', _('IPs/Networks/MACs'),
					_('macaddr|ip[/cidr]<br />'));
				o.datatype = 'or(ipaddr,macaddr)';
				o.rmempty = true;
				o.modalonly = true;

				o = s.option(form.Value, 'maxelem', _('Max Entries'),
					_('up to 65536 entries.'));
				o.datatype = 'port'; //covers 16 bit size
				o.modalonly = true;
				o.rmempty = true;
			} else {
				// this else section is intended to handle firewall3
				o = s.option(form.Value, 'external', _('Refer To External Set'));
				o.rmempty = true;
				o.optional = true;
				o.modalonly = true;

				o = s.option(form.ListValue, 'storage', _('Storage Method'));
				o.value('bitmap', _('bitmap')); //ipv4 only
				o.value('hash', _('hash'));
				o.value('list', _('list'));
				o.validate = function (section_id, value) {
					const family = this.section.formvalue(section_id, 'family');
					if (value.match(/bitmap/) && !family.match(/ipv4/))
						return _('bitmap is ipv4 only');
					return true;
				};
				o.modalonly = true;

				o = s.option(form.Value, 'iprange', _('IP (range)'),
					_('ip[/cidr]<br />' +
						'For use with Match datatypes: <code>*_ip</code>.'));
				o.datatype = 'ipaddr';
				o.depends({ family: 'ipv4', storage: 'bitmap', match: /_ip|_mac/ });
				o.depends({ storage: 'hash', match: /_ip/ });
				o.modalonly = true;

				o = s.option(form.DynamicList, 'entry', _('IPs/Networks'),
					_('ip[/cidr]<br />'));
				o.datatype = 'or(ipaddr,macaddr)';
				o.depends({ storage: 'hash', match: /_ip|_net|_mac/ });
				o.modalonly = true;

				o = s.option(form.Value, 'portrange', _('Port range'),
					_('fromport-toport'));
				o.datatype = 'neg(portrange)';
				o.depends({ family: 'ipv4', storage: 'bitmap', match: /_port/ });
				o.depends({ family: 'ipv4', storage: 'hash', match: /_port/ });
				o.depends({ family: 'ipv6', storage: 'hash', match: /_port/ });
				o.modalonly = true;

				o = s.option(form.Value, 'netmask', _('Netmask'));
				o.datatype = 'or(ip4prefix,ip6prefix)';
				o.depends({ family: 'ipv4', storage: 'bitmap', match: /_ip/ });
				o.depends({ storage: 'hash', match: /_ip/ });
				o.modalonly = true;

				o = s.option(form.Value, 'maxelem', _('Max Length'),
					_('up to 65536 entries.'));
				o.datatype = 'port';
				o.depends('storage', 'hash');
				o.depends('storage', 'list');
				o.modalonly = true;

				o = s.option(form.Value, 'hashsize', _('Initial Hash Size'));
				o.depends('storage', 'hash');
				o.placeholder = _('1024');
				o.modalonly = true;
			}

			o = s.option(form.FileUpload, 'loadfile', _('Include File'),
				_('Path to file of CIDRs, subnets, host IPs, etc.<br />'));
			o.root_directory = '/etc/luci-uploads';
			o.enable_delete = true;
			o.enable_upload = true;
			o.datatype = 'file';
			o.rmempty = true;
			o.modalonly = true;

			o = s.option(form.Value, 'timeout', _('Timeout'),
				_('Unit: seconds. Default <code>0</code> means the entry is added permanently to the set.<br />' +
					'Max: 2147483 seconds.'));
			o.placeholder = _('0');
			o.modalonly = true;
			o.rmempty = true;

			o = s.option(form.Flag, 'counters', _('Counters'),
				_('Enables packet and byte count tracking for the set.'));
			o.modalonly = true;
			o.rmempty = true;
			o.default = false;

			o = s.option(form.Flag, 'enabled', _('Enabled'));
			o.default = true;
			o.editable = true;
			o.modalonly = false;

			s.render = function () {
				return form.GridSection.prototype.render.apply(this, arguments).then(node => {
					return hybridtool.createSectionAccordion(title, node, isBlockHeader, this.cfgsections().length > 0);
				});
			};
		};

		// Block 1: Dual-stack IP Sets
		createSection(_('Dual-Stack IP Sets (IPv4 and IPv6)'), function (sid) {
			return uci.get('firewall', sid, 'family') === 'any';
		}, function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'family', 'any');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		}, true);

		// Block 2: IPv4 IP Sets
		createSection(_('IPv4 IP Sets'), function (sid) {
			const f = uci.get('firewall', sid, 'family');
			return (!f || f === 'ipv4');
		}, function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'family', 'ipv4');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		}, true);

		// Block 2: IPv6 IP Sets
		createSection(_('IPv6 IP Sets'), function (sid) {
			return uci.get('firewall', sid, 'family') === 'ipv6';
		}, function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'family', 'ipv6');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		}, true);

		return m.render().then(mapDom => {
			return E('div', { 'class': 'cbi-map' }, [
				E('h2', {}, [_('Firewall - IP Sets (Hybrid)')]),
				E('div', { 'class': 'cbi-map-descr' }, [_('firewall4 supports referencing and creating IP sets to simplify matching of large address lists without the need to create one rule per item to match. Port ranges in ipsets are unsupported by firewall4. Blocks are collapsible.')]),
				searchInput,
				mapDom
			]);
		});
	}
});