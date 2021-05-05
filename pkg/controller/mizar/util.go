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

type PortSelector struct {
	Protocol string `json:"protocol"`
	Port string `json:"port"`
}

type PodSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type NamespaceSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type IPBlock struct {
	Cidr string `json:"cidr,omitempty"`
	Except []string `json:"except,omitempty"`
}

type Allowed struct {
	P PodSelector `json:"podSelector,omitempty"`
	N NamespaceSelector `json:"namespaceSelector,omitempty"`
	I IPBlock `json:"ipBlock,omitempty"`
}

type IngressMsg struct {
	Ports []PortSelector `json:"ports"`
	ArrayRule []Allowed `json:"from"`
}

type EgressMsg struct {
	Ports []PortSelector `json:"ports"`
	ArrayRule []Allowed `json:"to"`
}

type PolicySpecMsg struct {
	PodSel PodSelector `json:"podSelector,omitempty"`
	In []IngressMsg `json:"ingress,omitempty"`
	Out []EgressMsg `json:"egress,omitempty"`
	Type []string `json:"policyTypes,omitempty"`
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
	policyJson, _ := json.Marshal(parseNetworkPolicySpecToMsg(policy.Spec))
	klog.Infof("NetworkPolicy: %s", string(policyJson))

	return &BuiltinsNetworkPolicyMessage{
		Name:          policy.Name,
		Namespace:     policy.Namespace,
		Tenant:        policy.Tenant,
		Policy:        string(policyJson),
	}
}

func parseNetworkPolicySpecToMsg(nps networking.NetworkPolicySpec) PolicySpecMsg {
	ingressMsg := []IngressMsg{}
	egressMsg := []EgressMsg{}
	typeMsg := []string{}

	podSelMsg := PodSelector {
		MatchLabels: nps.PodSelector.MatchLabels,
	}
	ingressMsg = parseNetworkPolicyIngressRulesToMsg(nps.Ingress)
	egressMsg = parseNetworkPolicyEgressRulesToMsg(nps.Egress)
	typeMsg = policyTypesToStringArry(nps.PolicyTypes)

	policyMsg := PolicySpecMsg {
		PodSel: podSelMsg,
		In: ingressMsg,
		Out: egressMsg,
		Type: typeMsg,
	}

	return policyMsg
}

func policyTypesToStringArry(pts []networking.PolicyType) []string {
	strPts := []string{}
	if pts != nil {
		for _, p := range pts {
			strPts = append(strPts, string(p))
		}
	}
	return strPts
}

func parseNetworkPolicyIngressRulesToMsg(npirs []networking.NetworkPolicyIngressRule) []IngressMsg {
	ingressPorts := []PortSelector{}
	froms := []Allowed{}
	ingressRules := []IngressMsg{}

	if len(npirs) == 0 {
		return nil
	}

	for _, npir := range npirs {
	        for _, port := range npir.Ports {
	                var protocol v1.Protocol
	                var portNum string
	                if port.Protocol != nil {
	                        protocol = *port.Protocol
	                } else {
	                        protocol = v1.ProtocolTCP
	                }
	                if port.Port.Type == intstr.Int {
	                        portNum = strconv.Itoa(int(port.Port.IntVal))
	                } else {
	                        portNum = port.Port.StrVal
	                }
	                sel := PortSelector{
	                        Protocol: string(protocol),
	                        Port: portNum,
	                }
			ingressPorts = append(ingressPorts, sel)
		}

		for _, from := range npir.From {
			if from.PodSelector != nil && from.NamespaceSelector != nil {
				podMsg := PodSelector{
					MatchLabels: from.PodSelector.MatchLabels,
				}
				namespaceMsg := NamespaceSelector{
					MatchLabels: from.NamespaceSelector.MatchLabels,
				}
				fromMsg := Allowed{
					P: podMsg,
					N: namespaceMsg,
				}
				froms = append(froms, fromMsg)
			} else if from.PodSelector != nil {
				podMsg := PodSelector{
					MatchLabels: from.PodSelector.MatchLabels,
				}
				fromMsg := Allowed{
					P: podMsg,
				}
				froms = append(froms, fromMsg)
			} else if from.NamespaceSelector != nil {
				namespaceMsg := NamespaceSelector{
					MatchLabels: from.NamespaceSelector.MatchLabels,
				}
				fromMsg := Allowed{
					N: namespaceMsg,
				}
				froms = append(froms, fromMsg)
			} else if from.IPBlock != nil {
				ipblockMsg := IPBlock{
					Cidr: from.IPBlock.CIDR,
					Except: from.IPBlock.Except,
				}
				fromMsg := Allowed{
					I: ipblockMsg,
				}
				froms = append(froms, fromMsg)
			}	
		}
		ingressMsg := IngressMsg{
			Ports: ingressPorts,
			ArrayRule: froms, 
		}
		ingressRules = append(ingressRules, ingressMsg)
	}
	return ingressRules
}

func parseNetworkPolicyEgressRulesToMsg(npers []networking.NetworkPolicyEgressRule) []EgressMsg {
	egressPorts := []PortSelector{}
	tos := []Allowed{}
	egressRules := []EgressMsg{}

	if len(npers) == 0 {
		return nil
	}

	for _, nper := range npers {
	        for _, port := range nper.Ports {
	                var protocol v1.Protocol
	                var portNum string
	                if port.Protocol != nil {
	                        protocol = *port.Protocol
	                } else {
	                        protocol = v1.ProtocolTCP
	                }
	                if port.Port.Type == intstr.Int {
	                        portNum = strconv.Itoa(int(port.Port.IntVal))
	                } else {
	                        portNum = port.Port.StrVal
	                }
	                sel := PortSelector{
	                        Protocol: string(protocol),
	                        Port: portNum,
	                }
			egressPorts = append(egressPorts, sel)
		}

		for _, to := range nper.To {
			if to.PodSelector != nil && to.NamespaceSelector != nil {
				podMsg := PodSelector{
					MatchLabels: to.PodSelector.MatchLabels,
				}
				namespaceMsg := NamespaceSelector{
					MatchLabels: to.NamespaceSelector.MatchLabels,
				}
				toMsg := Allowed{
					P: podMsg,
					N: namespaceMsg,
				}
				tos = append(tos, toMsg)
			} else if to.PodSelector != nil {
				podMsg := PodSelector{
					MatchLabels: to.PodSelector.MatchLabels,
				}
				toMsg := Allowed{
					P: podMsg,
				}
				tos = append(tos, toMsg)
			} else if to.NamespaceSelector != nil {
				namespaceMsg := NamespaceSelector{
					MatchLabels: to.NamespaceSelector.MatchLabels,
				}
				toMsg := Allowed{
					N: namespaceMsg,
				}
				tos = append(tos, toMsg)
			} else if to.IPBlock != nil {
				ipblockMsg := IPBlock{
					Cidr: to.IPBlock.CIDR,
					Except: to.IPBlock.Except,
				}
				toMsg := Allowed{
					I: ipblockMsg,
				}
				tos = append(tos, toMsg)
			}	
		}
		egressMsg := EgressMsg{
			Ports: egressPorts,
			ArrayRule: tos, 
		}
		egressRules = append(egressRules, egressMsg)
	}
	return egressRules
}
