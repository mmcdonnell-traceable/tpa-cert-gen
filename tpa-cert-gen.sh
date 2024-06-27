#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
  echo2 "This script must be run as root."
  exit 1
fi

# Unsets
unset -v TPAHOST
unset -v OPENSSLCNF
unset -v DEFAULT_DOMAIN

# Constants
EXIT_CLEAN=0
EXIT_ERR=1

# Generated Constants
STDDATE="$(date +"%Y.%m.%d-%H.%M.%S")"
BAKSUFFIX="${STDDATE}.bak"

SCRIPT=$(realpath ${BASH_SOURCE[0]})
SCRIPTSDIR=$( cd "$(dirname ${SCRIPT})" ; pwd );

function main() {
  # 1. Get Default Domain
  if [ -z "${DEFAULT_DOMAIN}" ]; then
    echo "To speed up data entry you will enter a default domain to help build out your CN and SAN entries where needed."
    echo2 "Example:\n\t'traceableai.svc'"
    prompt_text DEFAULT_DOMAIN "Please enter the default domain." "traceableai.svc"
  fi

  # 2. Get TPA Host Name
  if [ -z "${TPAHOST}" ]; then
    TPAHOST="$(hostname -f)"
    echo "Hostname not passed in. Assuming ${TPAHOST} for hostname."
  fi
  validate_hostname TPAHOST "${DEFAULT_DOMAIN}"

  # 3. Find the OpenSSL File - we need that for cert gen.
  get_openssl_file OPENSSLCNF

  # 4. SANs
  local SANS=""

  # 4a. Traceable Default Entries
  local TRACESANS="traceable-agent agent.traceableai agent.traceableai.svc"
  echo ""
  add_to_sanlist SANS "${TRACESANS}" "Traceable uses a few default SANs for Kubernetes." "${DEFAULT_DOMAIN}"

  # 4b. Local / IP Entries
  local ADDIP
  local IPLIST="localhost "
  get_ip_addresses IPLIST
  echo ""
  add_to_sanlist SANS "${IPLIST}" "Many customers like having direct access to the TPA via IP/Localhost" "${DEFAULT_DOMAIN}"

  # 4c. Custom Entries
  echo ""
  prompt_boolean ADDCUSTOM "Would you like to add any other host names or IPs to the SAN list?" "No"
  if [ ${ADDCUSTOM} == "Y" ]; then
    echo "  Note: if you do not enter an FQDN - you'll have the option to add it later"
    local NEWHOST="z"
    while [ ! -z "${NEWHOST}" ]; do
      read -p "Please enter a hostname (Blank to continue): " NEWHOST
      if [ ! -z "${NEWHOST}" ]; then
        prompt_boolean NHVAL "Would you like to DNS validate this hostname?" "Yes"
        if [ ${NHVAL} == "Y" ]; then
          validate_hostname NEWHOST "${DEFAULT_DOMAIN}"
        fi
      fi
    done
  fi

  generate_certs "${TPAHOST}" "${SANS}"

  exit_stage_left ${EXIT_CLEAN}
}

function add_to_sanlist() {
  if [ -z "${1}" -a -z "${4}" ]; then
    exit_stage_left ${EXIT_ERR} "You need to pass in:\n\tSAN List Variable\n\tContent List\n\tMessage\nDefault Domain\n\t(Optional) Force Add Domain"
  fi;

  # Parameters
  local -n __SANLIST=${1}
  local CONTENTLIST=${2}
  local MSG=${3}
  local DEF_DOMAIN=${4}
  local FORCE_ADD=${5:-"0"}

  local ADDITEM=""

  if [ "${__SANLIST:0-1}" != " " ]; then
    __SANLIST="${__SANLIST} "
  fi

  # 
  echo2 "${MSG}"
  for ITEM in ${CONTENTLIST}; do
    echo "  ${ITEM}"
  done;
  prompt_boolean ADDITEM "Would you like to add these to the SAN list now?" "Yes"
  if [ ${ADDITEM} == "Y" ]; then
    prompt_boolean VALIDATE "Would you like to DNS validate these entries?" "No"

    for ITEM in ${CONTENTLIST}; do
      if [ ${VALIDATE} == "Y" ]; then
        validate_hostname ITEM "${DEF_DOMAIN}" "${FORCE_ADD}"
      fi
      __SANLIST="${__SANLIST}${ITEM} "
    done;
  fi
}

function echo2 () {
  MSG=${1:-""}
  printf "${MSG}\n"
}

function exit_stage_left() {
  local ERRCODE=${1:-0}
  local ERRMSG=${2:-""}
  local OUTSTR=""
  if [ "${ERRCODE}" != "0" ]; then
    OUTSTR="ERROR: "
  fi
  OUTSTR="${OUTSTR}${ERRMSG}"
  echo2 "\n${OUTSTR}\n\nThank you for running ${SCRIPT}!"
  exit ${ERRCODE};
}

function generate_certs() {
  if [ -z "${1}" ]; then
    exit_stage_left ${EXIT_ERR} "[${0}] You need to pass in:\n\tCN\n\tList of SANs"
  fi
  local CN=${1}
  local SANLIST=${2}

  echo "${SANLIST}"; exit 1

  local SANSTR="subjectAltName="
  SANLIST=($SANLIST)
  for IND in "${!SANLIST[@]}"; do
    if [ "${SANSTR:0-1}" != "=" ]; then
      SANSTR="${SANSTR},"
    fi
    SANSTR="${SANSTR}DNS.$((${IND}+1)):${SANLIST[${IND}]}"
  done

  local KEYROOT="${SCRIPTSDIR}/keys/${STDDATE}"
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
      echo "Creating Directory: ${KEYROOT}"
      mkdir -p ${KEYROOT}
    fi
  fi

  local ROOTCAKEY="${KEYROOT}/root_ca.key"
  local ROOTCAPEM="${KEYROOT}/root_ca.pem"
  local DOMAINKEY="${KEYROOT}/${CN}.key"
  local DOMAINCSR="${KEYROOT}/${CN}.csr"
  local DOMAINPEM="${KEYROOT}/${CN}.pem"

  echo "Preparing to create key files:"
  echo "  Root CA Private Key File: ${ROOTCAKEY}"
  echo "  Root CA Public Cert:    ${ROOTCAPEM}"
  echo "  Domain Private Key File:  ${DOMAINKEY}"
  echo "  Domain Public Cert File:  ${DOMAINCSR}"
  echo "  Domain Cert Sig Req File: ${DOMAINPEM}"

  echo "Generating TPA Certs"

  # Generate Root CA
  echo "  1. Generating Root CA Private Key (${ROOTCAKEY})"
  openssl genrsa -out $ROOTCAKEY 4096 || exit_stage_left ${EXIT_ERR} "Couldn't Generate Root CA Private Key"

  # Generate Cert for Root CA
  echo "  2. Generating Root CA Cert (${ROOTCAPEM})"
  openssl req -x509 -new -nodes -sha256 -key $ROOTCAKEY -days 1825 \
    -subj "/CN=traceable-agent-ca" -out $ROOTCAPEM || exit_stage_left ${EXIT_ERR} "Couldn't Generate Root CA Cert"

  # 3. Generate the Certificate key
  echo "  3. Generating Private Key for ${CN} (${DOMAINKEY})"
  openssl genrsa -out $DOMAINKEY 4096 || exit_stage_left ${EXIT_ERR} "Couldn't Generate ${CN} Private Key"

  # 4. Generate the Certificate Request. Valid for 5years(1825 days)
  echo "  4a. Generating Cert Request (${DOMAINCSR})"
  openssl req -new -sha256 -key $DOMAINKEY \
    -subj "/CN=${CN}" -reqexts SAN -out $DOMAINCSR \
    -config <(cat ${OPENSSLCNF} <(printf "\n[SAN]\n${SANSTR}")) || exit_stage_left ${EXIT_ERR} "Couldn't Generate ${CN} CSR"

  echo "  4b. Validating CSR"
  openssl req -in $DOMAINCSR -noout -text || exit_stage_left ${EXIT_ERR} "Couldn't Validate ${CN} CSR"

  # 5. Generate the Certificate using the root CA
  echo "  5. Generating the Certificate (${DOMAINPEM})"
  openssl x509 -req -in $DOMAINCSR -CA $ROOTCAPEM -CAkey $ROOTCAKEY -CAcreateserial \
    -days 1825 -sha256 -out $DOMAINPEM -extfile <(printf "${SANSTR}") || exit_stage_left ${EXIT_ERR} "Couldn't Generate ${CN} Cert"
  
  # 5b. Quick verify
  echo "  6. Validating the cert works against its Root CA"
  openssl verify -CAfile ${ROOTCAPEM} ${DOMAINPEM} || exit_stage_left ${EXIT_ERR} "${CN} Cert doesn't validate against ${ROOTCAPEM}"

  prompt_boolean CERTCHECK "  7. (Optional) Do you want to see the contents of ${DOMAINPEM}" "No"
  if [ ${CERTCHECK} == "Y" ]; then
    openssl x509 -in $DOMAINPEM -text -noout
  fi

  echo2 "\n\nDo not forget to chown -R ${KEYROOT} if necessary.\nExample For Copy / Paste convenience:"
  echo2 "\tchown -R $(who am i | awk '{print $1}'):$(who am i | awk '{print $1}') ${KEYROOT}"
}

function get_ip_addresses () {
  local -n __IPLIST=${1:-""}
  local CMD="ip addr show"
  local CMDTEST="$(which ip)"
  if [ -z "${CMDTEST}" ]; then
    CMD="ifconfig"
  fi

  if [ "${__IPLIST:0-1}" != " " ]; then
    __IPLIST="${__IPLIST} "
  fi

  local IFACES=$($CMD | grep -E "^[0-9]:.*state (UP|UNKNOWN)" | awk '{print $2}' | sed -e 's/://g')
  for IFACE in ${IFACES}; do
    local IPINFO=$(${CMD} ${IFACE})
    IP=$(echo "${IPINFO}" | grep "inet " | awk '{print $2}' | awk -F '/' '{print $1}')

    __IPLIST="${__IPLIST}${IP} "
  done
}

function get_openssl_file() {
  local -n __OSSLC=${1:-""}
  local CNFFILE="openssl.cnf"

  if [ -z "${__OSSLC}" -o ! -f "${__OSSLC}" ]; then 
    echo "Searching for ${CNFFILE}"
    local OPTIONS=($(find / -type d \( -path /tmp -o -path /proc -o -path /sys -o -path /run -o -path /home \) -prune -o -name "${CNFFILE}"  -print 2>/dev/null))
    prompt_choice __OSSLC "Which OpenSSL File do you want to use?" "${OPTIONS[@]}"
  fi

  if [ ! -f "${__OSSLC}" ]; then
    exit_stage_left ${EXIT_ERR} "Couldn't find '${__OSSLC}' on filesystem"
  fi
}

function prompt_boolean() {
  if [ -z "${1}" ]; then
    exit_stage_left ${EXIT_ERR} "[${0}] You need to pass in:\n\tBoolean Varable\n\tMessage\n\tDefault"
  fi
  local -n __BOOL=${1}
  local MSG=${2}
  local DEFAULT=${3}
  
  local OPT="Z"
  # Set Choice to something stupid
  local CHOICE=""

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
  __BOOL=${CHOICE}
}

function prompt_choice() {
  if [ -z "${1}" ]; then
    echo2 "Error! You need to pass in a parameter!"
    echo2 "  ${0} 'Do you like apples?' ('Yes' 'No')"
    exit 1
  fi;
  local -n __CHOICE=${1}
  local MSG=${2}
  shift 2;
  local OPTIONS=("$@")

  local MIN=1
  local MAX=${#OPTIONS[@]}
  local OPT=-1
  local QUITWARN=0

  # Don't let while loops bleed into the function.
  __CHOICE="!@#$%^&*()"

  if [[ ${MAX} -gt 1 ]]; then
    while [[ "${OPT}" -lt ${MIN} || "${OPT}" -gt ${MAX} ]]; do
      for i in "${!OPTIONS[@]}"; do
        echo2 "$(($i+1))\t${OPTIONS[$i]}"
      done
      read -p "${MSG} " OPT
      if [[ "${OPT}" -ge ${MIN} && "${OPT}" -le ${MAX} ]]; then
        __CHOICE="${OPTIONS[$((${OPT}-1))]}"
      fi
    done;
  else
    __CHOICE="${OPTIONS[0]}"
    echo "No other option available. Choosing ${__CHOICE}"
  fi;

  if [ "Quit" == "${__CHOICE}" ]; then
    exit_stage_left ${EXIT_CLEAN} "You have chosen Quit."
  fi
}

function prompt_text() {
  if [ -z "${1}" ]; then
    exit_stage_left ${EXIT_ERR} "[${0}] You need to pass in:\n\tVarable\n\tMessage\n\tDefault"
  fi
  local -n __TEXT=${1}
  local MSG=${2}
  local DEFAULT=${3}

  local ACCEPTED="Z"

  while [ "${ACCEPTED}" != "Y" ]; do
    read -p "${MSG} (${DEFAULT})" __TEXT
    if [ -z "${__TEXT}" ]; then
      __TEXT=${DEFAULT}
    fi

    prompt_boolean ACCEPTED "You entered ${__TEXT}. Is this correct?" "Yes"
  done
}

function validate_hostname() {
  if [ -z "${1}" -a -z "${4}" ]; then
    exit_stage_left ${EXIT_ERR} "You need to pass in:\n\tFQDN Variable\nDefault Domain\n\t(Optional) Force Add Domain"
  fi;
  local -n __FQDN=${1}
  local DEF_DOMAIN=${2}
  local FORCE_ADD=${3:-"0"}
  local DOMAIN
  local ADDDOMAIN

  echo "Validating ${__FQDN}"

  # Validate its an FQDN
  if [[ ${__FQDN//[^.]} == "" ]]; then
    if [ "${FORCE_ADD}" == "0" ]; then
      prompt_boolean ADDDOMAIN "Hostname '${__FQDN}' is not an Fully Qualified Domain Name, Do you want to add a domain?" "Yes"
    else
      ADDDOMAIN="Y"
    fi

    if [ ${ADDDOMAIN} == "Y" ]; then
      if [ "${FORCE_ADD}" == "0" ]; then
        read -p "  Please enter the domain (${DEF_DOMAIN}): " DOMAIN
        if [ -z "${DOMAIN}" ]; then
          __FQDN="${__FQDN}.${DEF_DOMAIN}"
        else
          __FQDN="${__FQDN}.${DOMAIN}"
        fi
      else
        __FQDN="${__FQDN}.${DEF_DOMAIN}"
      fi
    fi
  fi

  # Validate it Resolves to literally anything. I'll take 127.0.0.1 even
  NSLOOKUP=$(nslookup ${__FQDN})

  #Whoopsie!
  if [ $? != 0 ]; then
    echo "${NSLOOKUP}"
    prompt_boolean CONTVAL "Hostname ${__FQDN} lookup failed. Do you want to continue?" "Yes"
    if [ ${CONTVAL} == "N" ]; then
      exit_stage_left ${EXIT_ERR} "Error: nslookup ${__FQDN} failed."
    fi
  fi

  echo "${NSLOOKUP}"
  prompt_boolean CONTVAL "Is this correct DNS Data?" "Yes"
  if [ ${CONTVAL} == "N" ]; then
    echo "Exit?"
    exit_stage_left ${EXIT_ERR} "Error: DNS details of ${__FQDN} were wrong."
  fi

  echo ""
}

while getopts "t:o:d:h" options; do         
  case "${options}" in
    t)
      TPAHOST="${OPTARG}"
      ;;
    o)
      OPENSSLCNF="${OPTARG}"
      ;;
    d)
      DEFAULT_DOMAIN="${OPTARG}"
      ;;
    h)
      exit_stage_left ${EXIT_CLEAN} "Usage: $0 [ -t \${TPA Hostname} ] [ -o \${OpenSSL Conf File} ] [ -d \${Default Domain Name} ]"
      ;;
    :)
      exit_stage_left ${EXIT_ERR} "-${options} requires an argument."
      ;;
    *)
      exit_stage_left ${EXIT_ERR} "Unknown Argument '-${options}'"
      ;;
  esac
done
shift $((OPTIND-1))

main