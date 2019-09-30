#!/usr/bin/env bash
# Update an existing certificate (possibly used by services) with new certificate+privkey files

# args: <name> <certificate_file>
function needs_update() {
	local NAME="$1"
	local CERTIFICATE_FILE="$2"
	[[ "$#" -ne 2 ]] && echo "usage: ${FUNCNAME[0]}: <name> <certificate_file>" && return 1

	local NEW="$(cat "$CERTIFICATE_FILE")"
	local OLD="$(sqlite3 /data/freenas-v1.db "SELECT cert_certificate FROM system_certificate WHERE cert_name = '$NAME'")"
	
	# Update if the certificate is out of date or if the web service is not patched (which occurs on reboot since /etc is a tmpfs)
	if [ "$NEW" != "$OLD" ] || ! grep -q "ec -in" /etc/ix.rc.d/ix-nginx; then
		return 0
	else
		return 1
	fi
}

# args: <name> <certificate_file> <key_file>
function import_certificate() {
	local NAME="$1"
	local CERTIFICATE_FILE="$2"
	local KEY_FILE="$3"
	[[ "$#" -ne 3 ]] && echo "usage: ${FUNCNAME[0]}: <name> <certificate_file> <key_file>" && return 1

	# TODO: ensure none contain a quote
	# Replace newlines with \n so it can be put in JSON:
	# https://superuser.com/questions/955935/how-can-i-replace-a-newline-with-its-escape-sequence
	CERTIFICATE="$(cat "$CERTIFICATE_FILE" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')"
	KEY="$(cat "$KEY_FILE" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')"

	# Basic validation
	[[ -z "$CERTIFICATE" ]] && echo "Certificate file was empty: $CERTIFICATE_FILE" && return 1
	[[ -z "$KEY" ]] && echo "Key file was empty: $KEY_FILE" && return 1

	# Import new certificate
	midclt call certificate.do_create "{\"create_type\": \"CERTIFICATE_CREATE_IMPORTED\", \"name\": \"$NAME\", \"certificate\": \"$CERTIFICATE\", \"privatekey\": \"$KEY\"}" > /dev/null
}

# Update a certificate in-place
# args: <old_certificate_name> <new_certificate_name>
function update_certificate() {
	local OLD_NAME="$1"
	local NEW_NAME="$2"
	[[ "$#" -ne 2 ]] && echo "usage: ${FUNCNAME[0]}: <old_certificate_name> <new_certificate_name>" && return 1

	# Replace the certificate in the FreeNAS settings database
	# Other options: https://stackoverflow.com/questions/3845718/update-table-values-from-another-table-with-the-same-user-name
	# Produces a line for each non-id column like: cert_name=(SELECT cert_name FROM system_certificate WHERE cert_name='$OLD_NAME')
	SET_CLAUSE="$(sqlite3 /data/freenas-v1.db ".schema system_certificate" | sed -r -e 's/CREATE TABLE[^(]*\(//' -e t1 -e d -e :1 -e 's/ *"([^"]+)"[^,]*(,)?/\1\2/g' -e 's/(^|,)((id)|(cert_name))($|,)/\1\5/g' -e "s/,*([^,]+)(,)?/\1=(SELECT \1 FROM system_certificate WHERE cert_name='$NEW_NAME')\2/g")"
	sqlite3 /data/freenas-v1.db <<- EOF
		UPDATE system_certificate
		SET $SET_CLAUSE
		WHERE cert_name = '$OLD_NAME'
	EOF

	
	# Replace the locally stored certificate file, which is used by some services (e.g. nginx for the web GUI)
	mv "/etc/certificates/$NEW_NAME.crt" "/etc/certificates/$OLD_NAME.crt"	
	mv "/etc/certificates/$NEW_NAME.key" "/etc/certificates/$OLD_NAME.key"	
}

# iXsystem's nginx generation script won't support Elliptic Curve keys until 11.3 so we need to patch it manually:
# https://redmine.ixsystems.com/issues/27665
function patch_ix_nginx_for_ec() {
	# Test with: service ix-nginx restart
	SCRIPT="/etc/ix.rc.d/ix-nginx"
	VERSION="$(midclt call system.info | sed -r 's/.*"version": "([^"]+)".*/\1/')"

	[[ ! "$VERSION" < "FreeNAS-11.3" ]] && return

	# Ignore exit status of 1 due to EOF
	read -r -d '' PATCH <<- 'EOF' || true
		216c216
		< 		${OPENSSL} rsa -in "${httpdkey}" -check -noout > /dev/null 2>&1
		---
		> 		${OPENSSL} ec -in "${httpdkey}" -noout > /dev/null 2>&1
		219c219
		< 		local safecert=$(${OPENSSL} rsa -in "${httpdkey}" -text -noout | grep "Private-Key" | egrep -o '[0-9]' | tr -d "\n")
		---
		> 		local safecert=$(${OPENSSL} ec -in "${httpdkey}" -text -noout 2>/dev/null | grep "Private-Key" | egrep -o '[0-9]' | tr -d "\n")
		221c221
		< 		if [ ${validcert} -eq 0 -a ${safecert} -ge 1024 ]; then
		---
		> 		if [ ${validcert} -eq 0 -a ${safecert} -ge 256 ]; then
	EOF

	# Check if the patch is already applied
	patch -RCtfs "$SCRIPT" >/dev/null <<< "$PATCH" && echo "$SCRIPT already patched" && return

	# Verify we can cleanly apply
	#patch -NCtnf /etc/ix.rc.d/ix-nginx <<< "$PATCH"
	#echo "$?"
	patch -NCtnfs "$SCRIPT" >/dev/null <<< "$PATCH" || { echo "$SCRIPT cannot be cleanly patched" >&2 && return 1; }

	# Apply the patch
	echo "Patching $SCRIPT"
	patch -Ntfns "$SCRIPT" <<< "$PATCH" && chmod 755 "$SCRIPT"
}

# Restart services to propogate changes of an in-place certificate update
# Could instead do something like:
# midclt call ftp.do_update '{"ssltls_certificate": 10}
function restart_services() {
	# Services defined in /usr/local/lib/python3.6/site-packages/middlewared/plugins/service.py:ServiceService
	midclt call service.restart 'ftp' > /dev/null
	midclt call service.restart 'webdav' > /dev/null

	# Web GUI
	# TODO: this will work on 11.2: midclt call system.general.ui_restart
	patch_ix_nginx_for_ec
	service ix-nginx restart
	midclt call service.restart 'http' > /dev/null
	midclt call service.restart 'django' >/dev/null
}

set -e

[[ "$EUID" -ne 0 ]] && echo "ERROR: Script must be run with root permissions" && exit 1

# Settings
CERTIFICATE_OLD="sigpanic"
PREFIX="/mnt/theabyss/iocage/jails/nginx/root/home/www/.caddy/acme/acme-v02.api.letsencrypt.org/sites/sigpanic.com/sigpanic.com"

needs_update "$CERTIFICATE_OLD" "$PREFIX.crt" || exit

CERTIFICATE_NEW="${CERTIFICATE_OLD}_$(date "+%Y%m%d")"
import_certificate "$CERTIFICATE_NEW" "$PREFIX.crt" "$PREFIX.key"
update_certificate "$CERTIFICATE_OLD" "$CERTIFICATE_NEW"
restart_services

echo "Successfully updated certificate: $CERTIFICATE_OLD"
echo "Certificate expiration date: $(openssl x509 -enddate -noout -in "$PREFIX.crt" | sed 's/notAfter=//')"
