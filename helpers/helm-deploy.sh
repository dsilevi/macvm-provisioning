#!/bin/bash

export config=$1 || exit
export namespace=$2 || exit
export service=$3 || exit
export additional_parameters=" $4 $5 $6 $7 $8"

pushd $service
echo "######## starting with deploy of $service with namespace $namespace in folder $(pwd)"

export chart=$(cat Chart.yaml |awk '/name:/ { print $2 }')
export version=$(cat Chart.yaml |awk '/version:/ { print $2 }')

echo "deploy $service with chart $chart version $version and additional_parameters ${additional_parameters}"

v="" ; for f in [cv]*.yaml ; do export v=${v}" -f "$f ; done

echo "---"
echo "helm --kubeconfig $config -n $namespace upgrade $service $chart --version $version --create-namespace --install $v ${additional_parameters}"
echo "---"
helm --kubeconfig $config -n $namespace upgrade $service $chart --version $version --create-namespace --install $v ${additional_parameters} --dry-run > /dev/null
if [[ $? != 0 ]] ; then echo "######### problem #########" ; popd ; exit ; fi
echo "$(date) deploy $service to $namespace"
helm --kubeconfig $config -n $namespace upgrade $service $chart --version $version --create-namespace --install $v ${additional_parameters}
echo "######## $(date) deploy $service to $namespace finished"

popd
