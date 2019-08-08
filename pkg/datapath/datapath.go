// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datapath

import (
	"io"
	"net"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/mac"
)

// Datapath is the interface to abstract all datapath interactions. The
// abstraction allows to implement the datapath requirements with multiple
// implementations
type Datapath interface {
	EndpointMapManager
	// Node must return the handler for node events
	Node() NodeHandler

	// LocalNodeAddressing must return the node addressing implementation
	// of the local node
	LocalNodeAddressing() NodeAddressing

	// WriteNodeConfig writes the implementation-specific configuration of
	// node-wide options into the specified writer.
	WriteNodeConfig(io.Writer, *LocalNodeConfiguration) error

	// WriteNetdevConfig writes the implementation-specific configuration
	// of configurable options to the specified writer. Options specified
	// here will apply to base programs and not to endpoints, though
	// endpoints may have equivalent configurable options.
	WriteNetdevConfig(io.Writer, DeviceConfiguration) error

	// WriteTemplateConfig writes the implementation-specific configuration
	// of configurable options for BPF templates to the specified writer.
	WriteTemplateConfig(w io.Writer, cfg EndpointConfiguration) error

	// WriteEndpointConfig writes the implementation-specific configuration
	// of configurable options for the endpoint to the specified writer.
	WriteEndpointConfig(w io.Writer, cfg EndpointConfiguration) error

	// InstallProxyRules creates the necessary datapath config (e.g., iptables
	// rules for redirecting host proxy traffic on a specific ProxyPort)
	InstallProxyRules(proxyPort uint16, ingress bool, name string) error

	// RemoveProxyRules creates the necessary datapath config (e.g., iptables
	// rules for redirecting host proxy traffic on a specific ProxyPort)
	RemoveProxyRules(proxyPort uint16, ingress bool, name string) error

	SyncEndpointsAndHostIPs() error
}

// EndpointFrontend is the interface to implement for an object to synchronize
// with the endpoint BPF map.
type EndpointFrontend interface {
	LXCMac() mac.MAC
	GetNodeMAC() mac.MAC
	GetIfIndex() int
	GetID() uint64
	IPv4Address() addressing.CiliumIPv4
	IPv6Address() addressing.CiliumIPv6
}

type EndpointMapManager interface {
	WriteEndpoint(frontend EndpointFrontend) error
	DeleteElement(frontend EndpointFrontend) []error
	DeleteEntry(ip net.IP) error
	DumpToMap() (ExistingEndpointsState, error)
}

type ExistingEndpointsState interface {
	Delete(ipAsString string)
	CleanupOldState(deleteFunc func(ip net.IP) error)
}
