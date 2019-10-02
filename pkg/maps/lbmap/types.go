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

package lbmap

import (
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// ServiceKey is the interface describing protocol independent key for services map v2.
type ServiceKey interface {
	bpf.MapKey

	// Return true if the key is of type IPv6
	IsIPv6() bool

	// Return the BPF map matching the key type
	Map() *bpf.Map

	// Set slave slot for the key
	SetSlave(slave int)

	// Get slave slot of the key
	GetSlave() int

	// Get frontend IP address
	GetAddress() net.IP

	// Get frontend port
	GetPort() uint16

	// Returns a RevNatValue matching a ServiceKey
	RevNatValue() RevNatValue

	// Delete entry identified with the key from the matching map
	MapDelete() error

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map v2.
type ServiceValue interface {
	bpf.MapValue

	// Set the number of backends
	SetCount(int)

	// Get the number of backends
	GetCount() int

	// Set reverse NAT identifier
	SetRevNat(int)

	// Get reverse NAT identifier
	GetRevNat() int

	// Set backend identifier
	SetBackendID(id loadbalancer.BackendID)

	// Get backend identifier
	GetBackendID() loadbalancer.BackendID

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey

	// Convert fields to network byte order.
	ToNetwork() ServiceValue
}

// BackendKey is the interface describing protocol independent backend key.
type BackendKey interface {
	bpf.MapKey

	// Return the BPF map matching the type
	Map() *bpf.Map

	// Set backend identifier
	SetID(loadbalancer.BackendID)

	// Get backend identifier
	GetID() loadbalancer.BackendID
}

// BackendValue is the interface describing protocol independent backend value.
type BackendValue interface {
	bpf.MapValue

	// Get backend address
	GetAddress() net.IP

	// Get backend port
	GetPort() uint16

	// Convert fields to network byte order.
	ToNetwork() BackendValue
}

// Backend is the interface describing protocol independent backend used by services v2.
type Backend interface {
	// Return the BPF map matching the type
	Map() *bpf.Map

	// Get key of the backend entry
	GetKey() BackendKey

	// Get value of the backend entry
	GetValue() BackendValue
}

type RevNatKey interface {
	bpf.MapKey

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatKey

	// Returns the key value
	GetKey() uint16
}

type RevNatValue interface {
	bpf.MapValue

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatValue
}

func svcFrontendAndBackends(svcKey ServiceKey, svcValue ServiceValue,
	backendID loadbalancer.BackendID, backend BackendValue) (*loadbalancer.L3n4AddrID, *loadbalancer.Backend) {

	var beBackend *loadbalancer.Backend

	feL3n4Addr := loadbalancer.NewL3n4Addr(loadbalancer.NONE, svcKey.GetAddress(), svcKey.GetPort())
	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       loadbalancer.ID(svcValue.GetRevNat()),
	}

	if backendID != 0 {
		beIP := backend.GetAddress()
		bePort := backend.GetPort()
		beProto := loadbalancer.NONE
		beBackend = loadbalancer.NewBackend(backendID, beProto, beIP, bePort)
	}

	return feL3n4AddrID, beBackend
}
