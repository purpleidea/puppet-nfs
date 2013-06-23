# here is some simple nfs::server usage including making the homes dir:
class { '::nfs::server':
	domain => "${::domain}",
	ipa => 'nfs',			# the ipa::client::service name
	kerberos => 'ipa',		# optional when we're using ipa
	shorewall => true,
}

file { '/export/':
	ensure => directory,		# make sure this is a directory
	recurse => false,		# don't recurse into directory!
	purge => false,			# don't purge unmanaged files!!
	force => false,			# don't purge subdirs and links
}

file { '/export/homes/':
	ensure => directory,		# make sure this is a directory
	recurse => false,		# don't recurse into directory!
	purge => false,			# don't purge unmanaged files!!
	force => false,			# don't purge subdirs and links
	require => File['/export/'],
}

# the $name here is the client mountpoint when we use: safety => false!
nfs::server::export { '/homes/':	# name is the client mountpoint
	export => '/export/homes/',
	rw => true,
	async => false,
	wdelay => true,		# if false then async must be false too
	rootsquash => true,
	sec => true,		# set true for automatic kerberos magic
	options => [],		# add any other options you might want!
	hosts => ["ws*.${domain}"],	# export to these hosts only...
	exported => true,	# create exported resources for clients
	tagas => 'homes',
	safety => false,	# be super clever (see the module docs)
	comment => 'Export home directories for ws*',
	require => File['/export/homes/'],
}

# and here is how you can collect / mount ~automatically on the client:
class { '::nfs::client':
	kerberos => true,
}

nfs::client::mount::collect { 'homes':	# match the $tagas from export!
	server => "${::hostname}.${::domain}",
	#suid => false,
	#clientaddr => "${::ipaddress}",	# use this if you want!
}

