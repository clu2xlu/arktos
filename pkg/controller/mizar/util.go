/*
Copyright 2020 Authors of Arktos.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mizar

import (
	"encoding/json"
	"strconv"
	"k8s.io/klog"
	"k8s.io/apimachinery/pkg/util/intstr"

	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
)

type EventType string

const (
	EventType_Create EventType = "Create"
	EventType_Update EventType = "Update"
	EventType_Delete EventType = "Delete"

	InternalIP v1.NodeAddressType = "InternalIP"
	ExternalIP v1.NodeAddressType = "ExternalIP"

	Arktos_Network_Name string = "arktos.futurewei.com/network"
)

type KeyWithEventType struct {
	EventType       EventType
	Key             string
	ResourceVersion string
}

type StartHandler func(interface{}, string)

func ConvertToServiceEndpointContract(endpoints *v1.Endpoints, service *v1.Service) *BuiltinsServiceEndpointMessage {
	backendIps := []string{}
	for _, subset := range endpoints.Subsets {
		for _, address := range subset.Addresses {
			backendIps = append(backendIps, address.IP)
		}
	}
	backendIpsJson, _ := json.Marshal(backendIps)

	ports := []*PortsMessage{}
	for _, port := range service.Spec.Ports {
		portsMessage := &PortsMessage{
			FrontendPort: strconv.Itoa(int(port.Port)),
			BackendPort:  strconv.Itoa(int(port.TargetPort.IntVal)),
			Protocol:     string(port.Protocol),
		}
		ports = append(ports, portsMessage)
	}
	portsJson, _ := json.Marshal(ports)

	klog.Infof("Endpoint Name: %s, Namespace: %s, Tenant: %s, Backend Ips: %s, Ports: %s",
	                        endpoints.Name, endpoints.Namespace, endpoints.Tenant, string(backendIpsJson), string(portsJson))

	return &BuiltinsServiceEndpointMessage{
		Name:           endpoints.Name,
		Namespace:      endpoints.Namespace,
		Tenant:         endpoints.Tenant,
		BackendIps:     []string{},
		Ports:          []*PortsMessage{},
		BackendIpsJson: string(backendIpsJson),
		PortsJson:      string(portsJson),
	}
}

func ConvertToPodContract(pod *v1.Pod) *BuiltinsPodMessage {
	var network string
	if value, exists := pod.Labels[Arktos_Network_Name]; exists {
		network = value
	} else {
		network = ""
	}

	klog.Infof("Pod Name: %s, HostIP: %s, Namespace: %s, Tenant: %s, Arktos network: %s",
			pod.Name, pod.Status.HostIP, pod.Namespace, pod.Tenant, network)

	return &BuiltinsPodMessage{
		Name:          pod.Name,
		HostIp:        pod.Status.HostIP,
		Namespace:     pod.Namespace,
		Tenant:        pod.Tenant,
		ArktosNetwork: network,
		Phase:         string(pod.Status.Phase),
	}
}

func ConvertToNodeContract(node *v1.Node) *BuiltinsNodeMessage {
	ip := ""
	for _, item := range node.Status.Addresses {
		if item.Type == InternalIP {
			ip = item.Address
			break
		}
	}

	klog.Infof("Node Name: %s, IP: %s", node.Name, ip)
	return &BuiltinsNodeMessage{
		Name: node.Name,
		Ip:   ip,
	}
}

func ConvertToNetworkPolicyContract(policy *networking.NetworkPolicy) *BuiltinsNetworkPolicyMessage {
	klog.Infof("NetworkPolicy Name: %s, Namespace: %s, Tenant: %s",
			policy.Name, policy.Namespace, policy.Tenant)
	jsonString, _ := json.Marshal(policy.Spec.PodSelector.MatchLabels)
	klog.Infof("PodSelector %s", jsonString)
	klog.Infof("Ingress %s", jsonStringNetworkPolicySpecIngressFrom(policy.Spec.Ingress))
	klog.Info("Egress %s", policy.Spec.Egress)

	return &BuiltinsNetworkPolicyMessage{
		Name:          policy.Name,
		Namespace:     policy.Namespace,
		Tenant:        policy.Tenant,
	}
}

func jsonStringNetworkPolicySpecIngressFrom(npirs []networking.NetworkPolicyIngressRule) string{
	type PortSelector struct {
		Protocol string
		Port string
	}
	type PodSelector struct {
		MatchLabels map[string]string
	}
	type PodSelectorMsg struct {
		P PodSelector `json:"PodSelector"`
	}
	type NamespaceSelector struct {
		MatchLabels map[string]string
	}
	type NamespaceSelectorMsg struct {
		N NamespaceSelector `json:"NamespaceSelector"`
	}
	type IPBlock struct {
		Cidr string
		Except []string
	}
	type IngressRule struct {
		Ports string
		From string
	}

	ingressPorts := []*PortSelector{}
	froms := []string{}
	rules := []string{}
	
	for _, npir := range npirs {
	        for _, port := range npir.Ports {
	                var proto v1.Protocol
	                var portNum string
	                if port.Protocol != nil {
	                        proto = *port.Protocol
	                } else {
	                        proto = v1.ProtocolTCP
	                }
	                if port.Port.Type == intstr.Int {
	                        portNum = strconv.Itoa(int(port.Port.IntVal))
	                } else {
	                        portNum = port.Port.StrVal
	                }
	                sel := &PortSelector{
	                        Protocol: string(proto),
	                        Port: portNum,
	                }
			ingressPorts = append(ingressPorts, sel)
		}
		portsJson, _ := json.Marshal(ingressPorts)
		klog.Infof("Ports Json %s", string(portsJson))

		for _, from := range npir.From {
			if from.PodSelector != nil && from.NamespaceSelector != nil {
				podMsg := PodSelector{
					MatchLabels: from.PodSelector.MatchLabels,
				}
				namespaceMsg := NamespaceSelector{
					MatchLabels: from.NamespaceSelector.MatchLabels,
				}
				pMsg := PodSelectorMsg{
					P: podMsg,
				}
				nMsg := NamespaceSelectorMsg{
					N: namespaceMsg,
				}
				podJson, _ := json.Marshal(pMsg)
				namespaceJson, _ := json.Marshal(nMsg)
				klog.Infof("pod1 Json %s", string(podJson))

				froms = append(froms, string(podJson))
				froms = append(froms, string(namespaceJson))
			} else if from.PodSelector != nil {
				podMsg := PodSelector{
					MatchLabels: from.PodSelector.MatchLabels,
				}
				pMsg := PodSelectorMsg{
					P: podMsg,
				}
				podJson, _ := json.Marshal(pMsg)
				klog.Infof("pod2 Json %s", string(podJson))

				froms = append(froms, string(podJson))
			} else if from.NamespaceSelector != nil {
				namespaceMsg := NamespaceSelector{
					MatchLabels: from.NamespaceSelector.MatchLabels,
				}
				nMsg := NamespaceSelectorMsg{
					N: namespaceMsg,
				}
				namespaceJson, _ := json.Marshal(nMsg)
				froms = append(froms, string(namespaceJson))
			} else if from.IPBlock != nil {
				ipblock := &IPBlock{
					Cidr: from.IPBlock.CIDR,
					Except: from.IPBlock.Except,
				}
				ipJson, _ := json.Marshal(ipblock)
				froms = append(froms, string(ipJson))
			}
		}
		fromsJson, _ := json.Marshal(froms)
		klog.Infof("Froms Json %s", froms)

		rule := &IngressRule{
			Ports: string(portsJson),
			From: string(fromsJson),
		}
		ruleJson, _ := json.Marshal(rule)
		rules = append(rules, string(ruleJson))
	}
	rulesJson, _ := json.Marshal(rules)
	return string(rulesJson)
}

