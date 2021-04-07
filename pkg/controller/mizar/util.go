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
	klog.Infof("NetworkPolicy Name: %s, Tenant: %s",
			policy.Name, policy.Tenant)

	//describeNetworkPolicySpec(policy.Spec, w)
	return &BuiltinsNetworkPolicyMessage{
		Name:          policy.Name,
		Tenant:        policy.Tenant,
	//	Spec:          string(policy.Spec),
	}
}

/*
func describeNetworkPolicySpec(nps networkingv1.NetworkPolicySpec, w PrefixWriter) {
	w.Write(LEVEL_0, "Spec:\n")
	w.Write(LEVEL_1, "PodSelector: ")
	if len(nps.PodSelector.MatchLabels) == 0 && len(nps.PodSelector.MatchExpressions) == 0 {
		w.Write(LEVEL_2, "<none> (Allowing the specific traffic to all pods in this namespace)\n")
	} else {
		w.Write(LEVEL_2, "%s\n", metav1.FormatLabelSelector(&nps.PodSelector))
	}
	w.Write(LEVEL_1, "Allowing ingress traffic:\n")
	printNetworkPolicySpecIngressFrom(nps.Ingress, "    ", w)
	w.Write(LEVEL_1, "Allowing egress traffic:\n")
	printNetworkPolicySpecEgressTo(nps.Egress, "    ", w)
	w.Write(LEVEL_1, "Policy Types: %v\n", policyTypesToString(nps.PolicyTypes))
}

func printNetworkPolicySpecIngressFrom(npirs []networkingv1.NetworkPolicyIngressRule, initialIndent string, w PrefixWriter) {
	if len(npirs) == 0 {
		w.Write(LEVEL_0, "%s%s\n", initialIndent, "<none> (Selected pods are isolated for ingress connectivity)")
		return
	}
	for i, npir := range npirs {
		if len(npir.Ports) == 0 {
			w.Write(LEVEL_0, "%s%s\n", initialIndent, "To Port: <any> (traffic allowed to all ports)")
		} else {
			for _, port := range npir.Ports {
				var proto corev1.Protocol
				if port.Protocol != nil {
					proto = *port.Protocol
				} else {
					proto = corev1.ProtocolTCP
				}
				w.Write(LEVEL_0, "%s%s: %s/%s\n", initialIndent, "To Port", port.Port, proto)
			}
		}
		if len(npir.From) == 0 {
			w.Write(LEVEL_0, "%s%s\n", initialIndent, "From: <any> (traffic not restricted by source)")
		} else {
			for _, from := range npir.From {
				w.Write(LEVEL_0, "%s%s\n", initialIndent, "From:")
				if from.PodSelector != nil && from.NamespaceSelector != nil {
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "NamespaceSelector", metav1.FormatLabelSelector(from.NamespaceSelector))
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "PodSelector", metav1.FormatLabelSelector(from.PodSelector))
				} else if from.PodSelector != nil {
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "PodSelector", metav1.FormatLabelSelector(from.PodSelector))
				} else if from.NamespaceSelector != nil {
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "NamespaceSelector", metav1.FormatLabelSelector(from.NamespaceSelector))
				} else if from.IPBlock != nil {
					w.Write(LEVEL_1, "%sIPBlock:\n", initialIndent)
					w.Write(LEVEL_2, "%sCIDR: %s\n", initialIndent, from.IPBlock.CIDR)
					w.Write(LEVEL_2, "%sExcept: %v\n", initialIndent, strings.Join(from.IPBlock.Except, ", "))
				}
			}
		}
		if i != len(npirs)-1 {
			w.Write(LEVEL_0, "%s%s\n", initialIndent, "----------")
		}
	}
}

func printNetworkPolicySpecEgressTo(npers []networkingv1.NetworkPolicyEgressRule, initialIndent string, w PrefixWriter) {
	if len(npers) == 0 {
		w.Write(LEVEL_0, "%s%s\n", initialIndent, "<none> (Selected pods are isolated for egress connectivity)")
		return
	}
	for i, nper := range npers {
		if len(nper.Ports) == 0 {
			w.Write(LEVEL_0, "%s%s\n", initialIndent, "To Port: <any> (traffic allowed to all ports)")
		} else {
			for _, port := range nper.Ports {
				var proto corev1.Protocol
				if port.Protocol != nil {
					proto = *port.Protocol
				} else {
					proto = corev1.ProtocolTCP
				}
				w.Write(LEVEL_0, "%s%s: %s/%s\n", initialIndent, "To Port", port.Port, proto)
			}
		}
		if len(nper.To) == 0 {
			w.Write(LEVEL_0, "%s%s\n", initialIndent, "To: <any> (traffic not restricted by source)")
		} else {
			for _, to := range nper.To {
				w.Write(LEVEL_0, "%s%s\n", initialIndent, "To:")
				if to.PodSelector != nil && to.NamespaceSelector != nil {
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "NamespaceSelector", metav1.FormatLabelSelector(to.NamespaceSelector))
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "PodSelector", metav1.FormatLabelSelector(to.PodSelector))
				} else if to.PodSelector != nil {
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "PodSelector", metav1.FormatLabelSelector(to.PodSelector))
				} else if to.NamespaceSelector != nil {
					w.Write(LEVEL_1, "%s%s: %s\n", initialIndent, "NamespaceSelector", metav1.FormatLabelSelector(to.NamespaceSelector))
				} else if to.IPBlock != nil {
					w.Write(LEVEL_1, "%sIPBlock:\n", initialIndent)
					w.Write(LEVEL_2, "%sCIDR: %s\n", initialIndent, to.IPBlock.CIDR)
					w.Write(LEVEL_2, "%sExcept: %v\n", initialIndent, strings.Join(to.IPBlock.Except, ", "))
				}
			}
		}
		if i != len(npers)-1 {
			w.Write(LEVEL_0, "%s%s\n", initialIndent, "----------")
		}
	}
}
*/
