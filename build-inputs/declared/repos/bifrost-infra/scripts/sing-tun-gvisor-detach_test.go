//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

type detachTestEndpoint struct {
	stack.LinkEndpoint
	dispatcher stack.NetworkDispatcher
	detaches int
}

func (e *detachTestEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	if dispatcher == nil { e.detaches++ }
}

type detachTestDispatcher struct { stack.NetworkDispatcher }

func TestBifrostLinkEndpointFilterPropagatesDetach(t *testing.T) {
	endpoint := &detachTestEndpoint{}
	filter := &LinkEndpointFilter{LinkEndpoint: endpoint}
	dispatcher := &detachTestDispatcher{}
	filter.Attach(dispatcher)
	if endpoint.dispatcher == nil || endpoint.dispatcher == dispatcher {
		t.Fatal("attached packets must still pass through the broadcast filter")
	}
	filter.Attach(nil)
	if endpoint.dispatcher != nil || endpoint.detaches != 1 {
		t.Fatal("detach was wrapped as a live dispatcher; native TUN reader cannot stop")
	}
	filter.Attach(nil)
	if endpoint.dispatcher != nil || endpoint.detaches != 2 {
		t.Fatal("repeated detach must remain detached")
	}
}
