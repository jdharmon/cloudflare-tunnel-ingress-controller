package controller

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func Test_withTunnelLoadBalancerStatus(t *testing.T) {
	wantIngress := []networkingv1.IngressLoadBalancerIngress{{
		Hostname: "tunnel.example.com",
		Ports: []networkingv1.IngressPortStatus{{
			Protocol: v1.ProtocolTCP,
			Port:     443,
		}},
	}}

	tests := []struct {
		name           string
		origin         networkingv1.Ingress
		hostname       string
		wantNeedUpdate bool
	}{
		{
			name:           "empty status needs an update",
			origin:         networkingv1.Ingress{},
			hostname:       "tunnel.example.com",
			wantNeedUpdate: true,
		},
		{
			name: "status already matches, no update needed",
			origin: networkingv1.Ingress{
				Status: networkingv1.IngressStatus{
					LoadBalancer: networkingv1.IngressLoadBalancerStatus{
						Ingress: wantIngress,
					},
				},
			},
			hostname:       "tunnel.example.com",
			wantNeedUpdate: false,
		},
		{
			name: "stale hostname needs an update",
			origin: networkingv1.Ingress{
				Status: networkingv1.IngressStatus{
					LoadBalancer: networkingv1.IngressLoadBalancerStatus{
						Ingress: []networkingv1.IngressLoadBalancerIngress{{Hostname: "old-tunnel.example.com"}},
					},
				},
			},
			hostname:       "tunnel.example.com",
			wantNeedUpdate: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newOrigin, needsUpdate := withTunnelLoadBalancerStatus(tt.origin, tt.hostname)
			if needsUpdate != tt.wantNeedUpdate {
				t.Fatalf("needsUpdate = %v, want %v", needsUpdate, tt.wantNeedUpdate)
			}
			if !needsUpdate {
				if newOrigin != nil {
					t.Fatalf("expected nil newOrigin when no update is needed, got %v", newOrigin)
				}
				return
			}
			if !reflect.DeepEqual(newOrigin.Status.LoadBalancer.Ingress, wantIngress) {
				t.Fatalf("newOrigin.Status.LoadBalancer.Ingress = %v, want %v", newOrigin.Status.LoadBalancer.Ingress, wantIngress)
			}
		})
	}
}
