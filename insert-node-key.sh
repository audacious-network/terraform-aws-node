#!/bin/bash

temp_dir=$(mktemp -d)

username=$1
if [ ! -n "${username}" ]; then
  echo "missing argument: username"
  echo "usage: ${0} \$username \$cname \$service_name \$pass_base"
  exit 1
fi

cname=$2
if [ ! -n "${cname}" ]; then
  echo "missing argument: cname"
  echo "usage: ${0} \$username \$cname \$service_name \$pass_base"
  exit 1
fi
domain=${cname#*.}

service_name=$3
if [ ! -n "${service_name}" ]; then
  echo "missing argument: service_name" 
  echo "usage: ${0} \$username \$cname \$service_name \$pass_base"
  exit 1
fi

pass_base=$4
if [ ! -n "${pass_base}" ]; then
  echo "missing argument: pass_base"
  echo "usage: ${0} \$username \$cname \$service_name \$pass_base"
  exit 1
fi

if ssh -o StrictHostKeyChecking=accept-new ${username}@${cname} "sudo mkdir -p /usr/share/${service_name}"; then
  echo "created or verified /usr/share/${service_name} on ${cname}"
else
  echo "failed to create or verify /usr/share/${service_name} on ${cname}"
  exit 1
fi

temp_file=${temp_dir}/$(uuidgen)
node_key=$(pass ${pass_base}/substrate-node-private/${domain}/${cname})
echo -n ${node_key} > ${temp_file}
if rsync --rsync-path='sudo rsync' ${temp_file} ${username}@${cname}:/usr/share/${service_name}/node-key; then
  echo "synced /usr/share/${service_name}/node-key to ${cname}"
else
  echo "failed to sync /usr/share/${service_name}/node-key to ${cname}"
  exit 1
fi
rm -rf ${temp_dir}
if ssh -o StrictHostKeyChecking=accept-new ${username}@${cname} "sudo chmod 0600 /usr/share/${service_name}/node-key"; then
  echo "set /usr/share/${service_name}/node-key to 0600 on ${cname}"
else
  echo "failed to set /usr/share/${service_name}/node-key to 0600 on ${cname}"
  exit 1
fi
