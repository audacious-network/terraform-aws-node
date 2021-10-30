#!/bin/bash

temp_dir=$(mktemp -d)

cname=$1
if [ ! -n "${cname}" ]; then
  echo "missing argument: cname"
  echo "usage: ${0} \$cname \$uname"
  exit 1
fi

uname=$2
if [ ! -n "${uname}" ]; then
  echo "missing argument: uname"
  echo "usage: ${0} \$cname \$uname"
  exit 1
fi

pass_base=$3
if [ ! -n "${pass_base}" ]; then
  echo "missing argument: pass_base"
  echo "usage: ${0} \$username \$cname \$service_name \$pass_base"
  exit 1
fi

PASSWORD_STORE_DIR=${PASSWORD_STORE_DIR:=${HOME}/.password-store}

if [ -f ${PASSWORD_STORE_DIR}/${pass_base}/letsencrypt/${cname}/privkey.pem.gpg ]; then
  for secret in cert chain fullchain privkey; do
    pass ${pass_base}/letsencrypt/${cname}/${secret}.pem > ${temp_dir}/${secret}1.pem
  done
  ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo mkdir -p /etc/letsencrypt/archive/${cname} /etc/letsencrypt/live/${cname}"
  rsync --rsync-path='sudo rsync' ${temp_dir}/*.pem ${uname}@${cname}:/etc/letsencrypt/archive/${cname}/
  rm -rf ${temp_dir}
  
  for secret in cert chain fullchain privkey; do
    if [ "${secret}" = "privkey" ]; then
      ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo chmod 0600 /etc/letsencrypt/archive/${cname}/${secret}1.pem"
    else
      ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo chmod 0644 /etc/letsencrypt/archive/${cname}/${secret}1.pem"
    fi
    ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo ln -rfs /etc/letsencrypt/archive/${cname}/${secret}1.pem /etc/letsencrypt/live/${cname}/${secret}.pem"
  done
  ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo systemctl stop nginx"
  ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo systemctl start nginx"
  ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo systemctl status nginx"
else
  mkdir -p ~/manta/ssl-certs/${cname}
  for secret in cert chain fullchain privkey; do
    timeout=$(date --date=5min +%s)
    while [ ! -f ${PASSWORD_STORE_DIR}/${pass_base}/letsencrypt/${cname}/${secret}.pem.gpg ] && [ ${timeout} -ge $(date +%s) ]; do
      if [ ! -s ~/manta/ssl-certs/${cname}/${secret}.pem ]; then
        if ssh -o StrictHostKeyChecking=accept-new ${uname}@${cname} "sudo cat /etc/letsencrypt/live/${cname}/${secret}.pem" > ~/manta/ssl-certs/${cname}/${secret}.pem && [ -s ~/manta/ssl-certs/${cname}/${secret}.pem ]; then
          echo "fetched /etc/letsencrypt/live/${cname}/${secret}.pem from ${cname}"
        else
          echo "failed to fetch /etc/letsencrypt/live/${cname}/${secret}.pem from ${cname}"
          sleep 10
        fi
      fi
      if [ -s ~/manta/ssl-certs/${cname}/${secret}.pem ]; then
        cat ~/manta/ssl-certs/${cname}/${secret}.pem | pass insert --multiline ${pass_base}/letsencrypt/${cname}/${secret}.pem
        if [ ! -f ${PASSWORD_STORE_DIR}/${pass_base}/letsencrypt/${cname}/${secret}.pem.gpg ]; then
          echo "failed to encrypt and persist ${pass_base}/letsencrypt/${cname}/${secret}.pem"
          exit 1
        fi
      fi
    done
    if [ ${timeout} -le $(date +%s) ]; then
      echo "timeout reached while attempting to fetch /etc/letsencrypt/live/${cname}/${secret}.pem from ${cname}"
      exit 1
    fi
  done
fi
