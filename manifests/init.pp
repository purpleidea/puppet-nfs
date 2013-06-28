# Simple nfs templating module by James
# Copyright (C) 2012-2013+ James Shubin
# Written by James Shubin <james@shubin.ca>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# TODO: using import is not recommended, and this import should be replaced.
# the reason that it's being used is it is currently the only way to include
# top level types that are written in puppet code (not ruby) without putting
# each of them in a separate top level module that has that associated name.
import 'common'			# include my puppet-common define's and classes

# TODO: manipulate the firewall to whitelist client ips by collected resources!

#class nfs::vardir {	# module vardir snippet
#	if "${::puppet_vardirtmp}" == '' {
#		if "${::puppet_vardir}" == '' {
#			# here, we require that the puppetlabs fact exist!
#			fail('Fact: $puppet_vardir is missing!')
#		}
#		$tmp = sprintf("%s/tmp/", regsubst($::puppet_vardir, '\/$', ''))
#		# base directory where puppet modules can work and namespace in
#		file { "${tmp}":
#			ensure => directory,	# make sure this is a directory
#			recurse => false,	# don't recurse into directory
#			purge => true,		# purge all unmanaged files
#			force => true,		# also purge subdirs and links
#			owner => root,
#			group => nobody,
#			mode => 600,
#			backup => false,	# don't backup to filebucket
#			#before => File["${module_vardir}"],	# redundant
#			#require => Package['puppet'],	# no puppet module seen
#		}
#	} else {
#		$tmp = sprintf("%s/", regsubst($::puppet_vardirtmp, '\/$', ''))
#	}
#	$module_vardir = sprintf("%s/nfs/", regsubst($tmp, '\/$', ''))
#	file { "${module_vardir}":		# /var/lib/puppet/tmp/nfs/
#		ensure => directory,		# make sure this is a directory
#		recurse => true,		# recursively manage directory
#		purge => true,			# purge all unmanaged files
#		force => true,			# also purge subdirs and links
#		owner => root, group => nobody, mode => 600, backup => false,
#		require => File["${tmp}"],	# File['/var/lib/puppet/tmp/']
#	}
#}

class nfs::package() {
	package { 'nfs-utils':
		ensure => present,
	}
}

class nfs::rpcbind() {
	package { 'rpcbind':
		ensure => present,
	}

	service { 'rpcbind':
		enable => true,			# start on boot
		ensure => running,		# ensure it stays running
		hasstatus => true,		# use status command to monitor
		hasrestart => true,		# use restart, not start; stop
		require => Package['rpcbind'],	# this is a dep. of: nfs-utils
	}
}

# NOTE: we don't support DES "allow_weak_crypto" for RHEL5 clients
class nfs::server(
	$domain = $::domain,		# defaults to facter fact
	$ipa = '',			# are we using a freeipa server?
	$kerberos = '',			# kerberos hostname
	$shorewall = false,
	$zone = 'net',
	$allow = 'all',
	$debug = false			# add -vvv flags to your sysconfig
) {
	$FW = '$FW'			# make using $FW in shorewall easier
	include nfs::package
	include nfs::rpcbind
	#include nfs::vardir
	##$vardir = $::nfs::vardir::module_vardir	# with trailing slash
	#$vardir = regsubst($::nfs::vardir::module_vardir, '\/$', '')

	$valid_domain = "${domain}"

	#if ("${ipa}" != '') or ("${kerberos}" != '') ...
	$bool_kerberos = "${ipa}${kerberos}" ? {	# clever hack
		'' => false,
		default => true,
	}

	$secure_nfs = $bool_kerberos ? {	# needed for /etc/sysconfig/nfs
		false => '',
		default => 'yes',
	}

	# does exportfs support looking in /etc/exports.d/*.exports ?
	$has_exports_dot_d = $operatingsystem ? {
		# TODO: add RHEL...
		'CentOS' => $operatingsystemrelease ? {
			6.4 => false,
			#7.0 => true,	# TODO ?
			default => false,	# unknown
		},
		default => false,		# unknown
	}

	# if we're not using using ipa, we need to supply this file...
	if "${ipa}" == '' {
		file { '/etc/krb5.conf':
			content => template('nfs/krb5.conf.erb'),
			owner => root, group => root, mode => 644, backup => false,
			before => Service['nfs'],
			require => Package['nfs-utils'],
			ensure => $kerberos ? {
				'' => absent,
				default => present,
			},
		}
	} else {
		# TODO: if we want to manage it here, it should be safe to do
	}

	file { '/etc/idmapd.conf':
		content => template('nfs/idmapd.conf.erb'),
		owner => root, group => root, mode => 644, backup => false,
		ensure => present,
		require => Package['nfs-utils'],
	}

	file { '/etc/sysconfig/nfs':
		content => template('nfs/sysconfig.nfs.erb'),
		owner => root, group => root, mode => 644, backup => false,
		ensure => present,
		require => Package['nfs-utils'],
	}

	$message = "# This file and /etc/exports.d/ are managed by puppet.\n"
	if $has_exports_dot_d {
		file { '/etc/exports':
			content => $message,
			owner => root,
			group => root,
			mode => 644,
			backup => false,
			ensure => present,
			before => Service['nfs'],
			notify => Exec['exportfs'],
			require => Package['nfs-utils'],
		}
	} else {
		# NOTE: we might as well use /etc/exports.d/ as the collect dir
		whole { '/etc/exports':
			dir => '/etc/exports.d/',
			pattern => '*.exports',	# only include files that match
			owner => root,
			group => root,
			mode => 644,
			backup => false,
			ensure => present,
			before => Service['nfs'],
			notify => Exec['exportfs'],
			require => Package['nfs-utils'],
		}

		file { '/etc/exports.d/README':
			content => $message,
			owner => root,
			group => root,
			mode => 644,
			backup => false,
			ensure => present,
			require => File['/etc/exports.d/'],	# from whole{}
		}
	}

	$require = $ipa ? {
		'' => [
			Service['rpcbind'],	# otherwise we get the error:
			# Starting NFS daemon: rpc.nfsd: writing fd to kernel
			# failed: errno 111 (Connection refused)
			#File['/etc/krb5.conf'],
			File['/etc/idmapd.conf'],
			File['/etc/sysconfig/nfs'],
		],
		default => [
			Ipa::Client::Service["${ipa}"],	# need the ipa service
			Service['rpcbind'],
			#File['/etc/krb5.conf'],
			File['/etc/idmapd.conf'],
			File['/etc/sysconfig/nfs'],
		],
	}

	# TODO: service nfslock ?
	# starting this service causes rpc.svcgssd to start (for it is used for
	# krb5) but it will exit without SECURE_NFS="yes" in /etc/sysconfig/nfs
	service { 'nfs':
		enable => true,			# start on boot
		ensure => running,		# ensure it stays running
		hasstatus => true,		# use status command to monitor
		hasrestart => true,		# use restart, not start; stop
		before => Exec['exportfs'],	# startup before we exportfs
		require => $require,
	}

	# reexport all dirs, synchronizing /var/lib/nfs/etab with /etc/exports.
	exec { '/usr/sbin/exportfs -r':
		logoutput => on_failure,
		refreshonly => true,
		require => Package['nfs-utils'],
		alias => 'exportfs',
	}

	# FIXME: consider allowing only certain ip's to the nfs server
	if $shorewall {
		if $allow == 'all' {
			$net = "${zone}"
		} else {
			$net = is_array($allow) ? {
				true => sprintf("${zone}:%s", join($allow, ',')),
				default => "${zone}:${allow}",
			}
		}
		####################################################################
		#ACTION      SOURCE DEST                PROTO DEST  SOURCE  ORIGINAL
		#                                             PORT  PORT(S) DEST
		shorewall::rule { 'nfs': rule => "
		ACCEPT  ${net}    $FW    tcp  2049
		", comment => 'Allow NFSv4 over tcp.'}

		# not used for nfsv4
		#shorewall::rule { 'rpcbind': rule => "
		#ACCEPT  ${net}    $FW    tcp  111
		#ACCEPT  ${net}    $FW    udp  111
		#", comment => 'Allow rpcbind over tcp/udp.'}
	}
}

define nfs::server::export(
	$export = '',	# $name is used by default unless we specify this here!
	$rw = false,			# export read only (true) or rw (false)
	$async = false,
	$wdelay = true,			# if false then async must be false too
	$rootsquash = true,
	$sec = '',			# set true for automatic kerberos magic
	# TODO: add other nfs server export options...
	$options = [],	# add on these additional options
	# pick one of these three as a mode: $hosts, $raw (a hash) or $manual
	# hostname formats: https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Storage_Administration_Guide/s2-nfs-hostname-formats.html
	# TODO: if <<||>> supported an in_array field, then we could do an auto
	# collect on the client hosts field like: <<| hosts.in_array($fqdn) |>>
	$hosts = [],		# also accepts a single string as a valid value
	$raw = {},			# TODO: should we validate the options?
	$manual = '',	# just give the full, exact string. overrides everyone!
	$exported = false,	# create exported resources to other nodes ?
	$tagas = undef,		# set a tag for the exported resources...
	# turn off safety, and be clever if the $name is the client mount value
	$safety = true,	# add a safety string to the exported mount option
	$comment = ''
) {
	include nfs::server

	$hostname = "${::hostname}"
	$domain = "${nfs::server::domain}"

	$bool_kerberos = $nfs::server::bool_kerberos	# pull from main class!

	$select_export = $export ? {
		'' => "${name}",
		default => "${export}",
	}

	# /etc/exports doesn't seem to use or like trailing slashes, so remove!
	$valid_export = sprintf("%s", regsubst($select_export, '\/$', ''))
	$check_export = sprintf("%s", regsubst($valid_export, '\/$', ''))
	if "${check_export}" != "${valid_export}" {
		fail("The '${select_export}' export has multiple trailing slashes!")
	}

	$valid_hosts = type($hosts) ? {
		'array' => $hosts,
		'string' => ["${hosts}"],
		#'hash' => [],
		default => [],
	}

	$valid_raw = type($raw) ? {
		'hash' => $raw,
		default => '',
	}

	# some simple consistency checking as a free bonus !
	if "${valid_hosts}" == [] and "${valid_raw}" == {} {
		fail("You must specify either (valid) $hosts or $raw.")
	}
	if "${valid_hosts}" != [] and "${valid_raw}" != '' {
		fail("You may specify either $hosts or $raw, but not both.")
	}
	if "${manual}" != '' and "${valid_export}" != '' {
		fail("You may specify either $export or $manual, but not both.")
	}

	# options...
	$valid_rw = $rw ? {
		true => 'rw',
		'rw' => 'rw',
		'ro' => 'ro',
		default => 'ro',
	}

	$valid_async = $async ? {
		true => 'async',
		'async' => 'async',
		'sync' => 'sync',
		default => 'sync',
	}

	# NOTE: no_wdelay is only available if the default sync option is also
	# specified
	$valid_wdelay = $wdelay ? {
		#false => 'no_wdelay',
		false => $async ? {
			true => '',	# ignore, but set a warning (below)
			'async' => '',
			'sync' => 'no_wdelay',
			default => 'no_wdelay',
		},
		'no_wdelay' => $async ? {
			true => '',	# ignore, but set a warning (below)
			'async' => '',
			'sync' => 'no_wdelay',
			default => 'no_wdelay',
		},
		'wdelay' => 'wdelay',
		default => 'wdelay',
	}
	if "${valid_wdelay}" == '' {
		warning("The no_wdelay option is only available with 'sync'.")
	}

	$valid_rootsquash = $rootsquash ? {
		false => 'no_root_squash',
		'no_root_squash' => 'no_root_squash',
		'all_squash' => 'all_squash',	# also supported...
		'root_squash' => 'root_squash',
		default => 'root_squash',
	}

	# TODO: validate $sec array using $sec_types and remove any duplicates!
	# TODO: if nfs::server::kerberos is '', disallow krb5 types...
	$sec_types = ['none', 'sys', 'krb5', 'krb5i', 'krb5p', 'lkey', 'lkeyi', 'lkeyp', 'spkm', 'spkmi', 'spkmp']
	$valid_sec = type($sec) ? {
		'string' => "sec=${sec}",
		'boolean' => $sec ? {
			true => 'sec=krb5p',		# magic kerberos value!
			default => '',
		},
		'array' => sprintf("sec=%s", join($sec, ':')),
		default => '',
	}

	# at the moment the $bool_kerberos flag is sort of like a specific
	# version of a $bool_security flag, which doesn't exist because we
	# don't yet support other mechanisms than kerberos at this time...
	if ! $bool_kerberos and "${sec}" != '' {
		fail('You must have security enabled to use $sec.')
	}

	# sec should go first, in case $options_other adds some more sec= on...
	$options_array = ["${valid_sec}", "${valid_rw}", "${valid_async}", "${valid_wdelay}", "${valid_rootsquash}"]
	$options_other = type($options) ? {
		'array' => $options,
		'string' => ["${options}"],
		default => [],
	}

	$valid_options = inline_template('<%= (options_array+options_other).delete_if {|x| x.empty? }.join(",") %>')

	$has_exports_dot_d = $nfs::server::has_exports_dot_d
	# NOTE: creating a uid with no slashes instead of using $name directly,
	# is needed, so that $name can be used as a mount value. Unfortunately,
	# the uniqueness required here in the frag $name can't contain slashes!
	# NOTE: there is still a collision risk if we want a mount with dashes,
	# but i ignore since that's really an edge case and is highly unlikely.
	# TODO: a simple sha1 or similar, but less ugly could even be better...
	$uid = sprintf("x%sx", regsubst($name, '/', '-', 'G'))	# replace / w -

	# format: export host1(options1) host2(options2) hostN(optionsN)
	if $has_exports_dot_d {
		file { "/etc/exports.d/${uid}.exports":
			content => template('nfs/exports.erb'),
			owner => root, group => root, mode => 644, backup => false,
			ensure => present,
			notify => Exec['exportfs'],
			before => Service['nfs'],	# TODO: is this okay ?
			require => File['/etc/exports.d/'],
		}
	} else {
		frag { "/etc/exports.d/${uid}.exports":
			content => template('nfs/exports.erb'),
			owner => root, group => root, mode => 644, backup => false,
			ensure => present,
			require => Package['nfs-utils'],
		}
	}

	# TODO: should we even do this ?
	# FIXME: should we offer different types ? eg: mount, automount ?
	if $exported {	# create exported resource mounts for clients
		@@nfs::client::mount { $name:
			mount => $safety ? {
				false => undef,
				true => '#',	# magic safety string!
			},
			export => sprintf("%s/", $valid_export),
			server => "${hostname}.${domain}",
			rw => $rw,	# NOTE: you can override on collector
			sec => $sec ? {
				true => true,	# pass through if auto kerberos
				default => undef,
			},
			tag => $tagas,		# set a tag for easy selection!
			ipa => $nfs::server::ipa,
		}
	}
}

class nfs::client(
	$domain = $::domain,		# defaults to facter fact
	$kerberos = '',
	$callback_port = 32764,		# arbitrary	# TODO: what is best ?
	$shorewall = false,
	$zone = 'net',
	$allow = 'all'
) {
	include nfs::package
	include nfs::rpcbind

	$valid_domain = "${domain}"

	$bool_kerberos = type($kerberos) ? {
		'boolean' => $kerberos ? {
			false => false,
			default => true,
		},
		'string' => "${kerberos}" ? {
			'' => false,
			default => true,
		},
		default => false,		# you can't specify anything :P
	}

	$secure_nfs = $bool_kerberos ? {	# needed for /etc/sysconfig/nfs
		false => '',
		default => 'yes',
	}

	if $bool_kerberos {
		# modprobe rpcsec_gss_krb5 if it's missing!
		# error messages without the modprobe were:
		# kernel: RPC: Couldn't create auth handle (flavor 390004)
		# kernel: gss_create: Pseudoflavor 390004 not found!
		exec { '/sbin/modprobe rpcsec_gss_krb5':
			logoutput => on_failure,
			unless => "/sbin/lsmod | /bin/grep -q '^rpcsec_gss_krb5'",
			alias => 'modprobe-rpcsec_gss_krb5',
		}
	}

	file { '/etc/idmapd.conf':
		content => template('nfs/idmapd.conf.erb'),
		owner => root, group => root, mode => 644, backup => false,
		ensure => present,
		before => Service['rpcidmapd'],	# TODO: is this even necessary?
		require => Package['nfs-utils'],
	}

	file { '/etc/sysconfig/nfs':
		content => template('nfs/sysconfig.nfs.erb'),
		owner => root, group => root, mode => 644, backup => false,
		ensure => present,
		require => Package['nfs-utils'],
	}

	# useful for NFSv4, version 4.1 doesn't need or use this...
	file { '/etc/modprobe.d/nfs-options-local.conf':	# TODO: does filename matter ?
		content => "options nfs callback_tcpport=${callback_port}\n",
		owner => root, group => root, mode => 644, backup => false,
		ensure => present,
		require => Package['nfs-utils'],	# require nfs exist :)
	}

	# FIXME: is this only needed with kerberos or does it have other uses ?
	if $bool_kerberos {
		# will not start without SECURE_NFS="yes" in /etc/sysconfig/nfs
		service { 'rpcgssd':
			enable => true,			# start on boot
			ensure => running,		# ensure it stays running
			hasstatus => true,		# use status command to monitor
			hasrestart => true,		# use restart, not start; stop
			require => File['/etc/sysconfig/nfs'],
		}
	}

	# TODO: is this needed if we're not using kerberos ?
	service { 'rpcidmapd':
		enable => true,			# start on boot
		ensure => running,		# ensure it stays running
		hasstatus => true,		# use status command to monitor
		hasrestart => true,		# use restart, not start; stop
		require => Package['nfs-utils'],	# this comes from here
	}

	# FIXME: consider allowing only certain ip's to the nfs server
	if $shorewall {
		if $allow == 'all' {
			$net = "${zone}"
		} else {
			$net = is_array($allow) ? {
				true => sprintf("${zone}:%s", join($allow, ',')),
				default => "${zone}:${allow}",
			}
		}
		####################################################################
		#ACTION      SOURCE DEST                PROTO DEST  SOURCE  ORIGINAL
		#                                             PORT  PORT(S) DEST

		# the server really does open a connection TO the client...
		# the nfs mailing list said it's okay if it doesn't work...
		if "${callback_port}" != '' {
			shorewall::rule { 'nfs': rule => "
			ACCEPT  ${net}    $FW    tcp  ${callback_port}
			", comment => 'Allow NFSv4 from server to client.'}
		}
	}
}

define nfs::client::mount(
	$mount = '',			# eg: /mnt/foo/ (defaults to $name)
	$export = '',			# eg: /export/foo/
	$server = '',			# eg: 203.0.113.42
	# TODO: add other nfs client mount options...
	$rw = false,			# mount read only (true) or rw (false)
	$suid = false,			# mount with suid/nosuid, (true/false)
	$sec = '',			# set true for sec=krb5p (the max sec)
	$clientaddr = '',
	$options = [],			# add on these additional options
	# TODO: is _netdev required or suggested ?
	$option_defaults = ['vers=4', 'hard', 'fg', '_netdev'],	# override if you want!
	$mounted = true,
	$ipa = '',			# the ipa service this corresponds to
	$comment = ''			# TODO: this is unused...
) {
	include nfs::client

	$bool_kerberos = $nfs::client::bool_kerberos	# pull from main class!

	$select_mount = $mount ? {
		'' => "${name}",
		default => "${mount}",
	}

	# this is a little hack so that exported resources don't get collected
	# accidentally without overriding the mount parameter. this is because
	# the nfs::server::export $name is used as the $name here, which isn't
	# what we probably want as a mount point. this reminds us to override!
	if "${select_mount}" == '#' {
		fail('You must override the $mount option in the collector!')
	}

	$slash_mount = sprintf("%s/", regsubst($select_mount, '\/$', ''))
	$valid_mount = sprintf("%s", regsubst($select_mount, '\/$', ''))
	$check_mount = sprintf("%s", regsubst($valid_mount, '\/$', ''))
	if "${check_mount}" != "${valid_mount}" {
		fail("The '${select_mount}' mount has multiple trailing slashes!")
	}

	$valid_export = sprintf("%s", regsubst($export, '\/$', ''))
	$check_export = sprintf("%s", regsubst($valid_export, '\/$', ''))
	if "${check_export}" != "${valid_export}" {
		fail("The '${select_export}' export has multiple trailing slashes!")
	}

	$valid_server = $server	# TODO: validate this somehow...

	# NOTE: some of the defaults here are *different* than what is provided
	# if you specify the 'defaults' mount option. these defaults are safer!
	$valid_rw = $rw ? {
		true => 'rw',
		'rw' => 'rw',
		'ro' => 'ro',
		default => 'ro',
	}

	$valid_suid = $suid ? {
		true => 'suid',
		'suid' => 'suid',
		'nosuid' => 'nosuid',
		default => 'nosuid',
	}

	$valid_sec = type($sec) ? {
		'string' => "sec=${sec}",
		'boolean' => $sec ? {
			true => 'sec=krb5p',	# magic kerberos value!
			default => '',
		},
		# TODO: does this support a list like on the server ?
		#'array' => sprintf("sec=%s", join($sec, ':')),
		default => '',
	}

	# at the moment the $bool_kerberos flag is sort of like a specific
	# version of a $bool_security flag, which doesn't exist because we
	# don't yet support other mechanisms than kerberos at this time...
	if ! $bool_kerberos and "${sec}" != '' {
		fail('You must have security enabled to use $sec.')
	}

	# NOTE: from the manual page of: nfs(5), section: clientaddr=n.n.n.n
	# Specifies a single IPv4 address (in dotted-quad form), or a
	# non-link-local IPv6 address, that the NFS client advertises to allow
	# servers to perform NFS version 4 callback requests against files on
	# this mount point. If the server is unable to establish callback
	# connections to clients, performance may degrade, or accesses to files
	# may temporarily hang.
	# If this option is not specified, the mount(8) command attempts to
	# discover an appropriate callback address automatically. The automatic
	# discovery process is not perfect, however. In the presence of
	# multiple client network interfaces, special routing policies, or
	# atypical network topologies, the exact address to use for callbacks
	# may be nontrivial to determine.
	$valid_clientaddr = $clientaddr ? {
		'' => '',
		default => "clientaddr=${clientaddr}",
	}

	$options_array = ["${valid_rw}", "${valid_suid}", "${valid_sec}", "${valid_clientaddr}"]
	$options_other = type($options) ? {
		'array' => $options,
		'string' => ["${options}"],
		default => [],
	}

	$valid_options = inline_template('<%= (options_array+options_other+option_defaults).delete_if {|x| x.empty? }.join(",") %>')

	# TODO: add support for the other available options...
	$valid_mounted = $mounted ? {
		true => mounted,
		default => unmounted,
	}

	# make an empty directory for mount point
	file { "${slash_mount}":		# this has a trailing dir slash
		ensure => directory,		# make sure this is a directory
		recurse => false,		# don't recurse into directory
		purge => false,			# don't purge unmanaged files
		force => false,			# don't purge subdirs and links
	}

	$require = $nfs::client::bool_kerberos ? {
		false => [
			File["${slash_mount}"],
			Service['rpcbind'],
			#Service['rpcgssd'],	# omit
			Service['rpcidmapd'],
		],
		default => [
			File["${slash_mount}"],
			Service['rpcbind'],
			Service['rpcgssd'],
			Service['rpcidmapd'],
		],
	}

	# the ipa_client_installed variable comes from the puppet-ipa facts
	if "${ipa}" == '' or ("${ipa_client_installed}" == 'true') {
		# eg: 203.0.113.42:/export/foo  /foo  nfs  hard,fg,rw,nosuid 0 0
		mount { "${valid_mount}":	# this should have no trailing slash...
			atboot => true,	# TODO: i think this is the same as auto/noauto
			ensure => $valid_mounted,
			device => "${valid_server}:${valid_export}",
			fstype => 'nfs',	# this means nfs4 by default on CentOS6
			options => "${valid_options}",
			dump => '0',		# fs_freq: 0 to skip file system dumps
			pass => '0',		# fs_passno: 0 to skip fsck on boot
			require => $require,
		}
	}
}

define nfs::client::mount::collect(	# $name is the $tagas value from export
	$server = '',
	$clientaddr = '',		# FIXME: should i offer the $ipaddress by default ?
	$suid = '',
	$comment = ''			# TODO: unused
) {
	$valid_server = "${server}" ? {
		'' => '',		# TODO: can we ever guess ?
		default => "${server}",
	}
	if "${valid_server}" == '' {
		fail('You must specify an nfs $server.')
	}

	if "${clientaddr}" == '' {
		if "${suid}" == '' {
			Nfs::Client::Mount <<| tag == "${name}" and server == "${valid_server}" |>> {
				#clientaddr => "${clientaddr}",
				# FIXME: will this undef work, and allow us to
				# avoid the hierarchial nesting ? will it use
				# the value it came with, or will it use the
				# default! the fact that there are two choices
				# means there is a logical dilemna! oh puppet
				#suid => "${suid}" ? {
				#	'' => undef,
				#	default => $suid,
				#},
			}
		} else {
			Nfs::Client::Mount <<| tag == "${name}" and server == "${valid_server}" |>> {
				#clientaddr => "${clientaddr}",
				suid => $suid,
			}
		}
	} else {
		if "${suid}" == '' {
			Nfs::Client::Mount <<| tag == "${name}" and server == "${valid_server}" |>> {
				clientaddr => "${clientaddr}",
			}
		} else {
			Nfs::Client::Mount <<| tag == "${name}" and server == "${valid_server}" |>> {
				clientaddr => "${clientaddr}",
				suid => $suid,
			}
		}
	}
}

