#!/bin/bash

temp_dir=$(mktemp -d)

username=$1
if [ ! -n "${username}" ]; then
  echo "missing argument: username"
  echo "usage: ${0} \$username \$cname \$key_variant \$service_name \$pass_base"
  exit 1
fi

cname=$2
if [ ! -n "${cname}" ]; then
  echo "missing argument: cname"
  echo "usage: ${0} \$username \$cname \$key_variant \$service_name \$pass_base"
  exit 1
fi
domain=${cname#*.}

key_variant=$3
if [ ! -n "${key_variant}" ]; then
  echo "missing argument: key_variant"
  echo "usage: ${0} \$username \$cname \$key_variant \$service_name \$pass_base"
  exit 1
fi

service_name=$4
if [ ! -n "${service_name}" ]; then
  echo "missing argument: service_name"
  echo "usage: ${0} \$username \$cname \$key_variant \$service_name \$pass_base"
  exit 1
fi

pass_base=$5
if [ ! -n "${pass_base}" ]; then
  echo "missing argument: pass_base"
  echo "usage: ${0} \$username \$cname \$key_variant \$service_name \$pass_base"
  exit 1
fi

# generate the author_insertKey payload and send to the remote host filesystem
temp_file=${temp_dir}/$(uuidgen).json
echo '{
  "jsonrpc":"2.0",
  "id":1,
  "method":"author_insertKey",
  "params": [
    "<audi/aura/babe/beef/gran/imon>",
    "<mnemonic phrase>",
    "<public key>"
  ]
}' | jq \
  --arg key_variant ${key_variant} \
  --arg mnemonic "$(pass ${pass_base}/${domain}/substrate-${key_variant}-mnemonic/${cname})" \
  --arg public $(pass ${pass_base}/${domain}/substrate-${key_variant}-public/${cname}) \
  '. | .params[0] = $key_variant | .params[1] = $mnemonic | .params[2] = $public' > ${temp_file}
if rsync ${temp_file} ${username}@${cname}:/home/${username}/${key_variant}.json; then
  echo "payload file {temp_file} rsynced to ${username}@${cname}:/home/${username}/${key_variant}.json"
else
  echo "payload file {temp_file} NOT rsynced to ${username}@${cname}:/home/${username}/${key_variant}.json"
fi
rm -rf ${temp_dir}

# enable unsafe rpc (required for author_insertKey)
enable_unsafe_rpc_script=()
enable_unsafe_rpc_script+=( "systemctl is-active --quiet ${service_name}.service && sudo systemctl stop ${service_name}.service;" )
enable_unsafe_rpc_script+=( "[ -f /var/log/${service_name}/stderr.log ] && sudo mv /var/log/${service_name}/stderr.log /var/log/${service_name}/stderr-$(date --utc --iso-8601=seconds).log;" )
enable_unsafe_rpc_script+=( "sudo sed -i 's/--rpc-methods safe/--rpc-methods unsafe/I' /etc/systemd/system/${service_name}.service;" )
enable_unsafe_rpc_script+=( "sudo systemctl daemon-reload;" )
enable_unsafe_rpc_script+=( "sudo systemctl start ${service_name}.service;" )
if ssh -o StrictHostKeyChecking=accept-new ${username}@${cname} "${enable_unsafe_rpc_script[*]}"; then
  echo "${cname} ${service_name}.service restarted with '--rpc-methods unsafe'"
else
  echo "${cname} ${service_name}.service NOT restarted with '--rpc-methods unsafe'"
  echo "enable_unsafe_rpc_script: ${enable_unsafe_rpc_script[*]}"
fi

sleep 30

# insert session key
insert_session_key_script=()
insert_session_key_script+=( "curl -vH 'Content-Type: application/json;charset=utf-8' --data @/home/${username}/${key_variant}.json http://localhost:9933;" )
insert_session_key_script+=( "rm /home/${username}/${key_variant}.json;" )
if ssh -o StrictHostKeyChecking=accept-new ${username}@${cname} "${insert_session_key_script[*]}"; then
  echo "${username}@${cname}:/home/${username}/${key_variant}.json payload applied with author_insertKey"
else
  echo "${username}@${cname}:/home/${username}/${key_variant}.json payload NOT applied with author_insertKey"
  echo "insert_session_key_script: ${insert_session_key_script[*]}"
fi

sleep 30

# disable unsafe rpc
disable_unsafe_rpc_script=()
disable_unsafe_rpc_script+=( "systemctl is-active --quiet ${service_name}.service && sudo systemctl stop ${service_name}.service;" )
disable_unsafe_rpc_script+=( "[ -f /var/log/${service_name}/stderr.log ] && sudo mv /var/log/${service_name}/stderr.log /var/log/${service_name}/stderr-$(date --utc --iso-8601=seconds).log;" )
disable_unsafe_rpc_script+=( "sudo sed -i 's/--rpc-methods unsafe/--rpc-methods safe/I' /etc/systemd/system/${service_name}.service;" )
disable_unsafe_rpc_script+=( "sudo systemctl daemon-reload;" )
disable_unsafe_rpc_script+=( "sudo systemctl start ${service_name}.service;" )
if ssh -o StrictHostKeyChecking=accept-new ${username}@${cname} "${disable_unsafe_rpc_script[*]}"; then
  echo "${cname} ${service_name}.service restarted with '--rpc-methods safe'"
else
  echo "${cname} ${service_name}.service NOT restarted with '--rpc-methods safe'"
  echo "disable_unsafe_rpc_script: ${disable_unsafe_rpc_script[*]}"
fi
