#!/usr/bin/env bash
# Adapted from https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309

if [[ $EUID -ne 0 ]]; then
  echo2 "This script must be run as root."
  exit 1
fi

# Set $1 import
HOSTNAME=${1:-"$(hostname -f)"}
OPENSSLCNF=${2:-""}

STDDATE="$(date +"%Y.%m.%d-%H.%M.%S")"
BAKSUFFIX="${STDDATE}.bak"

SCRIPT=$(realpath ${BASH_SOURCE[0]})
SCRIPTSDIR=$( cd "$(dirname ${SCRIPT})" ; pwd );

function main() {
  # echo2 "DEBUG START - PRESCRIPT CHECK"
  # ls -al /etc/ssl/
  # prompt_boolean DEBUG "  Does this look good?" "No"
  # if [ ${DEBUG} == "N" ]; then
  #   exit 99
  # fi
  # echo2 "DEBUG END"

  host_validation

  get_openssl_file OPENSSLCNF

  echo2 "Keys Directory Creation:"
  # TODO: If we need to do different revisioning than DTTM
  # Here's the logic.
  # INDEX=1
  local KEYROOT="${SCRIPTSDIR}/keys/${STDDATE}"  # .${INDEX}"
  # while [ -d ${KEYROOT} ]; do
  #   INDEX=$((INDEX++))
  #   KEYROOT="${SCRIPTSDIR}/keys/${STDDATE}.${INDEX}"
  # done

  prompt_boolean MKDIRKEYS "  Would you like to create the new directory: ${KEYROOT}?" "Yes"
  if [ ${MKDIRKEYS} == "Y" ]; then
    mkdir -p ${KEYROOT}
  else
    KEYROOT=""
    while [ -z "${KEYROOT}" ]; do
      read -p "Please enter a directory: " KEYROOT
      
      OUTPUTSTR="  You typed in '${KEYROOT}'. It does "
      if [ ! -d "${KEYROOT}" ]; then 
        OUTPUTSTR+="*not* "
      fi
      OUTPUTSTR+="exist. Is that correct?"

      prompt_boolean USEGOOD ${OUTPUTSTR} "Yes"
      if [ ${USEGOOD} == "N" ]; then
        KEYROOT=""
      fi
    done
    if [ ! -d "${KEYROOT}" ]; then
      echo2"Creating Directory: ${KEYROOT}"
      mkdir -p ${KEYROOT}
    fi
  fi

  ROOTCAKEY="${KEYROOT}/root_ca.key"
  ROOTCAPEM="${KEYROOT}/root_ca.pem"
  DOMAINKEY="${KEYROOT}/${HOSTNAME}.key"
  DOMAINCSR="${KEYROOT}/${HOSTNAME}.csr"
  DOMAINPEM="${KEYROOT}/${HOSTNAME}.pem"

  echo2 "Preparing to create key files:"
  echo2 "  Root CA Private Key File: ${ROOTCAKEY}"
  echo2 "  Root CA Public Cert:      ${ROOTCAPEM}"
  echo2 "  Domain Private Key File:  ${DOMAINKEY}"
  echo2 "  Domain Public Cert File:  ${DOMAINCSR}"
  echo2 "  Domain Cert Sig Req File: ${DOMAINPEM}"

  # {{- $altNames := list ( printf "agent.%s" .Release.Namespace ) ( printf "agent.%s.svc" .Release.Namespace ) -}}
  # {{- $ca := genCA (printf "%s-ca" .Chart.Name) 3650 -}}
  # {{- $cert := genSignedCert .Chart.Name nil $altNames 3650 $ca -}}

  echo2 "Generating certs for TPA!"
  # 1. Generate the root CA key
  echo2 "  1. Generating Root CA Private Key (${ROOTCAKEY})"
  openssl genrsa -out $ROOTCAKEY 4096

  # 2. Generate the self-signed root CA. Valid for 5years(1825 days)
  # -subj "/emailAddress=tim@traceable.ai/C=US/ST=California/L=San Francisco/O=Traceable AI, Inc./OU=Engineering/CN=agent.traceableai" \
  echo2 "  2. Generating Root CA Cert (${ROOTCAPEM})"
  openssl req -x509 -new -nodes -sha256 -key $ROOTCAKEY -days 1825 \
      -subj "/CN=traceable-agent-ca" \
      -out $ROOTCAPEM

  # 3. Generate the Certificate key
  echo2 "  3. Generating Private Key for ${HOSTNAME} (${DOMAINKEY})"
  openssl genrsa -out $DOMAINKEY 4096
  # 4. Generate the Certificate Request. Valid for 5years(1825 days)
  #
  #
  # -subj "/emailAddress=tim@traceable.ai/C=US/ST=California/L=San Francisco/O=Traceable AI, Inc./OU=Engineering/CN=agent.traceableai" \
  # a printf with more alternative names
  # <(printf "\n[SAN]\nsubjectAltName=DNS.1:agent.traceableai,DNS.2:agent.traceableai.svc,DNS.3:localhost,DNS.4:0.0.0.0,DNS.5:host.docker.internal,DNS.6:127.0.0.1")) \
  echo2 "  4a. Generating Cert Request (${DOMAINCSR})"
  openssl req -new -sha256 -key $DOMAINKEY \
      -subj "/CN=${HOSTNAME}" \
      -reqexts SAN \
      -config <(cat ${OPENSSLCNF} \
          <(printf "\n[SAN]\nsubjectAltName=DNS.1:traceable-agent,DNS.2:agent.traceableai,DNS.3:agent.traceableai.svc")) \
      -out $DOMAINCSR

  # 4b. Quick verify
  openssl req -in $DOMAINCSR -noout -text && echo2 "  4b. Cert Signing Request Valid!"
  # There is a bug in x509 command which does not allow the subjectAltName to be copied over from the csr. So we use the
  # -extfile cmd line option. See https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309#gistcomment-3034183
  #
  # -extfile <(printf "subjectAltName=DNS.1:agent.traceableai,DNS.2:agent.traceableai.svc,DNS.3:localhost,DNS.4:0.0.0.0,DNS.5:host.docker.internal,DNS.6:127.0.0.1")
  # 5. Generate the Certificate using the root CA
  echo2 "  5. Generating the Certificate (${DOMAINPEM})"
  openssl x509 -req -in $DOMAINCSR -CA $ROOTCAPEM -CAkey $ROOTCAKEY -CAcreateserial -days 1825 -sha256 -out $DOMAINPEM \
    -extfile <(printf "subjectAltName=DNS.1:agent.traceableai,DNS.2:agent.traceableai.svc")
  
  # 5b. Quick verify
  echo2 "  6. Validating the cert works against its Root CA"
  openssl verify -CAfile ${ROOTCAPEM} ${DOMAINPEM}

  prompt_boolean CERTCHECK "  7. (Optional) Do you want to see the contents of ${DOMAINPEM}" "No"
  if [ ${CERTCHECK} == "Y" ]; then
    openssl x509 -in $DOMAINPEM -text -noout
  fi

  echo2 "\n\nDo not forget to chown -R ${KEYROOT} if necessary.\nFor Copy / Paste convenience:"
  echo2 "\tchown -R $(who am i):$(who am i) ${KEYROOT}"
}

function echo2 () {
  MSG=${1:-""}
  printf "${MSG}\n"
}

function get_openssl_file() {
	local -n __RET=${1}
	local OSSLCNF="openssl.cnf"

  if [ -z ${__RET} -o ! -f ${__RET} ]; then 
    if [ ! -f ${__RET} ]; then
      echo2 "Couldn't find ${__RET}"
    fi
    echo2 "Searching for ${OSSLCNF}"
    OPTIONS=($(find / -name ${OSSLCNF} 2>/dev/null))
    prompt_choice __RET "Which OpenSSL File are we wanting to use?" "${OPTIONS[@]}"
  fi

  echo2 "OpenSSL File: ${__RET}"
	
  # Edit: I thought I needed to backup openssl.cnf
  # NOPE! ITS CHUCK TESTA!

  # prompt_boolean BACKUP "  Do you want to backup ${__RET}?" "No"
  # if [ ${BACKUP} == "Y" ]; then
  #   echo2 "Backing up ${OPENSSLCNF}"
  #   cp ${OPENSSLCNF} "${OPENSSLCNF}.${BAKSUFFIX}"
  # fi

}

function host_validation() {
  echo2 "Running ${HOSTNAME} validation"
  # Is it an FQDN?
  if [[ ${HOSTNAME//[^.]} != "" ]]; then
    echo2 "Hostname is an FQDN"
  else
    prompt_boolean ADDFQDN "  Hostname is not an FQDN - do you want to add a domain?" "Yes"
    if [ ${ADDFQDN} == "Y" ]; then
      echo2 "    Example domain: lab.traceable.ai"
      read -p "    Please enter the domain: " FQDN
      HOSTNAME="${HOSTNAME}.${FQDN}"
    fi
  fi

  echo2 "  Performing nslookup on '${HOSTNAME}'"
  NSLOOKUP=$(nslookup ${HOSTNAME})
  if [ $? != 0 ]; then
    echo2 "*******DNS Lookup Failed! Cannot Continue!*******";
    echo2 "${NSLOOKUP}"
    exit 99
  fi

  echo2 "${NSLOOKUP}"
  prompt_boolean DNSDATA "    Is this correct DNS Data?" "Yes"
  if [ ${DNSDATA} != "Y" ]; then
    echo2 "*******DNS Data Incorrect! Cannot Continue!*******";
    exit 99
  fi

  echo2 "Cert Subject: ${HOSTNAME}"
}

function prompt_boolean() {
  if [ -z "${1}" ]; then
    echo2 "Error! You need to pass in a parameter and default!"
    echo2 "  ${0} 'Do you like apples?' 'Yes'"
    exit 1
  fi;
  local -n __RET=${1}
  local MSG=${2}
  local DEFAULT=${3}
  
  local OPT="Z"
  # Set Choice to something stupid
  local CHOICE="Z"

  while [ "${CHOICE}" != "Y" -a "${CHOICE}" != "N" ]; do
    read -p "${MSG} (${DEFAULT})" OPT
    if [ -z "${OPT}" ]; then
      OPT="$(echo ${DEFAULT^} | head -c 1)"
    else
      OPT=$(echo ${OPT^} | head -c 1)
    fi
    if [ ${OPT} == "Y" -o ${OPT} == "N" ]; then
      CHOICE=${OPT}
    fi
  done
  __RET=${CHOICE}
}

function prompt_choice() {
  if [ -z "${1}" ]; then
    echo2 "Error! You need to pass in a parameter!"
    echo2 "  ${0} 'Do you like apples?' ('Yes' 'No')"
    exit 1
  fi;
  local -n CHOICE=${1}
  local MSG=${2}
  shift 2;
  local OPTIONS=("$@")

  local MIN=1
  local MAX=${#OPTIONS[@]}
  local OPT=-1
  CHOICE="!@#$%^&*()"

  if [[ ${MAX} -gt 1 ]]; then
    while [[ "${OPT}" -lt ${MIN} || "${OPT}" -gt ${MAX} ]]; do
      for i in "${!OPTIONS[@]}"; do
        echo2 "$(($i+1))   ${OPTIONS[$i]}"
      done
      read -p "${MSG} " OPT
      if [[ "${OPT}" -ge ${MIN} && "${OPT}" -le ${MAX} ]]; then
        CHOICE="${OPTIONS[$((${OPT}-1))]}"
      fi
    done;
  else
    CHOICE="${OPTIONS[0]}"
  fi;
}

main
