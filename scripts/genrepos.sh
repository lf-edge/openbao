#!/bin/bash

set -euxo pipefail

export createrepo="createrepo_c"
export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical

if ! command -v sudo 2>/dev/null ; then
	# Shim sudo to support running in a container without it.
	#
	# $ podman run --mount "type=bind,source=$PWD,destination=/openbao" --workdir /openbao -it ubuntu:latest bash /openbao/scripts/genrepos.sh
	function sudo() {
		"$@"
	}
fi

function install_deps() {(
	sudo apt update
	sudo apt install -y wget jq curl tree dpkg-dev reprepro
	sudo apt install -y createrepo-c || build_createrepo
	"$createrepo" --version
)}

# createrepo and createrepo_c are no longer packaged for Ubuntu all ubuntu
# releases.
#
# See also: https://launchpad.net/ubuntu/jammy/amd64/createrepo-c
function build_createrepo() {
	(
		sudo apt install -y libcurl4-openssl-dev libbz2-dev libxml2-dev libssl-dev zlib1g-dev pkg-config libglib2.0-dev liblzma-dev libsqlite3-dev librpm-dev libzstd-dev python3-dev cmake
		git clone https://github.com/rpm-software-management/createrepo_c /tmp/createrepo git
		cd /tmp/createrepo
		mkdir build && cd build && cmake ..
		make -j
	)

	createrepo="/tmp/createrepo/build/src/createrepo_c"
}

# Fetch the latest OpenBao release information and compare to cache; if
# we're the latest, assume we're done. Make sure we copy the updated
# release info as the very last thing.
function fetch_release_info() {
	curl -sSL \
	  -H "Accept: application/vnd.github+json" \
	  -H "X-GitHub-Api-Version: 2022-11-28" \
	  https://api.github.com/repos/openbao/openbao/releases > /tmp/release.json

	ls website/build/repos
	if [ -e website/build/repos/release.json ]; then
		local cached
		local latest
		cached="$(jq -r '.[0].id' < website/build/repos/release.json)"
		latest="$(jq -r '.[0].id' < /tmp/release.json)"
		if [ "x$cached" = "$latest" ]; then
			echo "Latest release ($latest) is the cached release"
			exit 0
		fi

		# When we're rebuilding the cache, clear it to remove old releases.
		echo "Continuing as cached ($cached) != latest ($latest)"
		rm -rf website/build/repos/linux
	fi
}

# Build RPM repositories, one for each arch. Don't re-download packages
# that already exist.
function build_repos_rpms() {(
	local repo_base="website/build/repos/linux/rpm"

	# Download the release RPMs.
	jq -r '.[0] | .. | .browser_download_url? | select(. != null)' < /tmp/release.json |
		sed '/\(alpha\|beta\)/d' |
		grep -i '\.rpm$' |
	while read -r rpm; do
		local arch
		local name
		arch="$(grep -o '_linux_[a-zA-Z0-9]*\.rpm' <<< "$rpm" | sed 's/\(_linux_\|\.rpm$\)//g')"
		name="$(basename "$rpm")"

		local dir="$repo_base/$arch"
		mkdir -p "$dir"
		wget --no-verbose "$rpm" --output-document "$dir/$name"
	done

	# Build the RPM repository
	for dir in "$repo_base"/*; do
		(
			cd "$dir"
			"$createrepo" .
		)
	done
)}

# Build Debian repositories.
function build_repos_deb() {(
	local repo_base="website/build/repos/linux/deb"
	mkdir -p "$repo_base"
	cd $repo_base

	# Create the reprepro configuration.
	local conf_base="conf"
	mkdir -p "$conf_base"
	cat > "$conf_base/distributions" <<_EOF
Origin: OpenBao - Official
Label: OpenBao
Suite: stable
Codename: stable
Architectures: amd64 armel armhf arm64 ppc64el riscv64 s390x
Components: main
Description: Official apt repository for OpenBao
SignWith: E617DCD4065C2AFC0B2CF7A7BA8BC08C0F691F94
_EOF
	cat > "$conf_base/options" <<_EOF
verbose
basedir $PWD
_EOF

	# Download the release DEBs and add them.
	jq -r '.[0] | .. | .browser_download_url? | select(. != null)' < /tmp/release.json |
		sed '/\(alpha\|beta\)/d' |
		grep -i '\.deb$' |
	while read -r deb; do
		local name
		name="$(basename "$deb")"

		wget --no-verbose "$deb" --output-document "$name"
		reprepro --delete --component=main --ignore=undefinedtarget includedeb stable "$name"
	done
)}

# Build all repositories
function build_repos() {(
	build_repos_rpms
	build_repos_deb

	# Arch repositories cannot be built as repo-add from pacman is not built
	# for Ubuntu or distributed separately from Arch.

	tree website/build/repos
	du -h --max-depth=1 website/build/repos
)}

# Copy the built release information into the website build.
function copy_release_info() {(
	cp /tmp/release.json website/build/repos/release.json
)}

function main() {(
	mkdir -p website/build/repos
	install_deps
	fetch_release_info
	build_repos
	copy_release_info
)}
main "$@"
