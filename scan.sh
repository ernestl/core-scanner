#!/bin/bash

# Inspired by https://github.com/canonical/vulnerability-management-scanning/blob/main/secscan/scanners.py#L1190

core=$1

PACKAGE_LIST="package-list.txt"
CORE_MANIFEST="usr/share/snappy/dpkg.yaml"
CORE_NAME="name.txt"

echo "1. Check dependencies"
echo ""
if ! command -v snap >/dev/null 2>&1; then
   echo "Error: this script requires \"snapd\""
   exit 1
else
   version=$(snap --version | awk '$1 == "snap" {print $2}')
   echo "Found \"snapd\" version $version"
fi

if ! command -v yq >/dev/null 2>&1; then
   echo "Error: this script requires \"yq\""
   exit 1
else
   version=$(jq --version)
   echo "Found \"jq\" version $version"
fi

if ! command -v osv-scanner >/dev/null 2>&1; then
   echo "Error: this script requires \"osv-scanner\""
   exit 1
else
   version=$(osv-scanner --version | grep '^osv-scanner version:' | cut -d' ' -f3)
   echo "Found \"osv-scanner\" version $version"
fi
echo ""

echo "2. Extract package manifest from $core"
echo ""
manifest=$(basename "$CORE_MANIFEST")
curdir=$(pwd)
tmpdir=$(mktemp -d)
(  
   cd "$tmpdir" || echo "Error: cannot change directory to $tmpdir"
   echo "Download $core"
   snap download "$core" --stable
   if ! find . -name "$core*.snap" | grep -q .; then 
      echo "Error: cannot find downloaded core snap"
      exit 1
   else
      snap_name=$(find . -name "$core*.snap")
   fi
   
   echo "Copy package manifest $CORE_MANIFEST to $curdir."
   unsquashfs ./*.snap >/dev/null 2>&1
   cp "squashfs-root/$CORE_MANIFEST" "$curdir"
   rm -rf squashfs-root
   if ! find "$curdir" -name "$manifest" | grep -q .; then
      echo "Error: cannot find extracted package manifest"
      exit 1
   fi

   name="$(basename "$snap_name")"
   file="$curdir/$CORE_NAME"
   echo "Write core snap name $name into file $file"
   echo "$name" > "$file"
)
rm -rf "$tmpdir"
echo ""

echo "3. Generate package list file named $PACKAGE_LIST from yaml manifest file $manifest."
echo ""
mapfile -t packages < <(yq -r '.packages[]' "$manifest")

rm -f "$PACKAGE_LIST"
for pkg in "${packages[@]}"; do
    echo "$pkg" >> "$PACKAGE_LIST"
done

printf "The first 5 lines:\n%s\n" "$(head -n 5 "$PACKAGE_LIST")"
echo ""

echo "4. Generate OSV lockfiles from the package list for the relevant ecosystems"
echo ""
echo "Calculating ecosystems"
snap_name=$(cat $CORE_NAME)
ecosystems=()

uc_version=16
case "$snap_name" in
    core[0-9]*)
	uc_version=${snap_name%%_*}
	uc_version=${uc_version#core}
        ;;
    core_*)
        ;;
    *)
        echo "Error: not a core base snap"
	exit 1
        ;;
esac

# Example: https://osv.dev/vulnerability/UBUNTU-CVE-2024-6174
ecosystems+=("Ubuntu:$uc_version.04:LTS")
ecosystems+=("Ubuntu:Pro:$uc_version.04:LTS")

echo "Generate lockfiles"
lockfiles=()
for ecosystem in "${ecosystems[@]}"; do
	lockfile="osv-lockfile-$ecosystem.json"
	ecosystems_json=$(printf '%s\n' "$ecosystem" | jq -R . | jq -s .)

	jq -n \
	  --argjson ecosystems "$ecosystems_json" '
	{
	  results: [
	    {
	      packages: [
		($ARGS.positional[]
		  | capture("^(?<name>[^=]+)=(?<version>.+)$")
		) as $pkg
		| $ecosystems[]
		| {
		    package: {
		      ecosystem: .,
		      name: $pkg.name,
		      version: $pkg.version
		    }
		  }
	      ]
	    }
	  ]
	}
	' --args "${packages[@]}" > "$lockfile"

	printf "The first 10 line of $lockfile:\n%s\n" "$(head -n 10 "$lockfile")"
	lockfiles+=("$lockfile")
	echo""
done

echo "5. Perform OSV scans for the relevant ecosystems"
echo""
core_name=$(cat $CORE_NAME)

for lockfile in "${lockfiles[@]}"; do
	result="result_${core_name}_${lockfile%.json}.md"
	osv-scanner --lockfile osv-scanner:"$lockfile" -f markdown > "$result"

	echo "Writing result for scan based on $lockfile to $result."
done
echo ""

echo "6. Done"
