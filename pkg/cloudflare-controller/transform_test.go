package cloudflarecontroller

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/exposure"
	"github.com/cloudflare/cloudflare-go"
	"k8s.io/utils/ptr"
)

func Test_fromExposureToCloudflareIngress(t *testing.T) {
	type args struct {
		ctx      context.Context
		exposure exposure.Exposure
	}
	tests := []struct {
		name    string
		args    args
		want    *cloudflare.UnvalidatedIngressRule
		wantErr bool
	}{
		{
			name: "deleted exposure",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					IsDeleted: true,
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid exposure",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "http://10.0.0.1:80",
					PathPrefix:    "/",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname:      "ingress.example.com",
				Path:          "^/.*$",
				Service:       "http://10.0.0.1:80",
				OriginRequest: nil,
			},
			wantErr: false,
		},
		{
			name: "ssh scheme drops path",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ssh.example.com",
					ServiceTarget: "ssh://10.0.0.1:22",
					PathPrefix:    "/*",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname:      "ssh.example.com",
				Path:          "",
				Service:       "ssh://10.0.0.1:22",
				OriginRequest: nil,
			},
			wantErr: false,
		},
		{
			name: "tcp scheme drops path",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "tcp.example.com",
					ServiceTarget: "tcp://10.0.0.1:5432",
					PathPrefix:    "/",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname:      "tcp.example.com",
				Path:          "",
				Service:       "tcp://10.0.0.1:5432",
				OriginRequest: nil,
			},
			wantErr: false,
		},
		{
			name: "prefix path",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "http://10.0.0.1:80",
					PathPrefix:    "/prefix",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname:      "ingress.example.com",
				Path:          "^/prefix(/.*)?$",
				Service:       "http://10.0.0.1:80",
				OriginRequest: nil,
			},
			wantErr: false,
		},
		{
			name: "exact path",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "http://10.0.0.1:80",
					PathPrefix:    "/openapi.json",
					PathType:      exposure.PathTypeExact,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname:      "ingress.example.com",
				Path:          `^/openapi\.json$`,
				Service:       "http://10.0.0.1:80",
				OriginRequest: nil,
			},
			wantErr: false,
		},
		{
			name: "prefix path with trailing slash normalizes",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "http://10.0.0.1:80",
					PathPrefix:    "/api/",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname:      "ingress.example.com",
				Path:          "^/api(/.*)?$",
				Service:       "http://10.0.0.1:80",
				OriginRequest: nil,
			},
			wantErr: false,
		},
		{
			name: "prefix path with regex metacharacters is escaped",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "http://10.0.0.1:80",
					PathPrefix:    "/v1.0",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname:      "ingress.example.com",
				Path:          `^/v1\.0(/.*)?$`,
				Service:       "http://10.0.0.1:80",
				OriginRequest: nil,
			},
			wantErr: false,
		},
		{
			name: "contains http-host-header",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:       "ingress.example.com",
					ServiceTarget:  "http://10.0.0.1:80",
					PathPrefix:     "/prefix",
					PathType:       exposure.PathTypePrefix,
					IsDeleted:      false,
					HTTPHostHeader: ptr.To("foo.internal"),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/prefix(/.*)?$",
				Service:  "http://10.0.0.1:80",
				OriginRequest: &cloudflare.OriginRequestConfig{
					HTTPHostHeader: ptr.To("foo.internal"),
				},
			},
			wantErr: false,
		},
		{
			name: "https with origin-server-name",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:         "ingress.example.com",
					ServiceTarget:    "https://10.0.0.1:443",
					PathPrefix:       "/",
					PathType:         exposure.PathTypePrefix,
					IsDeleted:        false,
					OriginServerName: ptr.To("bar.internal"),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "https://10.0.0.1:443",
				OriginRequest: &cloudflare.OriginRequestConfig{
					NoTLSVerify:      ptr.To(true),
					OriginServerName: ptr.To("bar.internal"),
				},
			},
		},
		{
			name: "https with different http-host-header and origin-server-name",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:         "ingress.example.com",
					ServiceTarget:    "https://10.0.0.1:443",
					PathPrefix:       "/",
					PathType:         exposure.PathTypePrefix,
					IsDeleted:        false,
					HTTPHostHeader:   ptr.To("foo.internal"),
					OriginServerName: ptr.To("bar.internal"),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "https://10.0.0.1:443",
				OriginRequest: &cloudflare.OriginRequestConfig{
					NoTLSVerify:      ptr.To(true),
					HTTPHostHeader:   ptr.To("foo.internal"),
					OriginServerName: ptr.To("bar.internal"),
				},
			},
		}, {
			name: "https should enable no-tls-verify by default",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "https://10.0.0.1:443",
					PathPrefix:    "/",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "https://10.0.0.1:443",
				OriginRequest: &cloudflare.OriginRequestConfig{
					NoTLSVerify: ptr.To(true),
				},
			},
		}, {
			name: "https with no-tls-verify enabled",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:              "ingress.example.com",
					ServiceTarget:         "https://10.0.0.1:443",
					PathPrefix:            "/",
					PathType:              exposure.PathTypePrefix,
					IsDeleted:             false,
					ProxySSLVerifyEnabled: ptr.To(false),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "https://10.0.0.1:443",
				OriginRequest: &cloudflare.OriginRequestConfig{
					NoTLSVerify: ptr.To(true),
				},
			},
		}, {
			name: "https with no-tls-verify disabled",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:              "ingress.example.com",
					ServiceTarget:         "https://10.0.0.1:443",
					PathPrefix:            "/",
					PathType:              exposure.PathTypePrefix,
					IsDeleted:             false,
					ProxySSLVerifyEnabled: ptr.To(true),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "https://10.0.0.1:443",
				OriginRequest: &cloudflare.OriginRequestConfig{
					NoTLSVerify: ptr.To(false),
				},
			},
		}, {
			name: "all origin request fields set on http target",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:               "ingress.example.com",
					ServiceTarget:          "http://10.0.0.1:80",
					PathPrefix:             "/",
					PathType:               exposure.PathTypePrefix,
					IsDeleted:              false,
					ConnectTimeout:         ptr.To(30 * time.Second),
					TLSTimeout:             ptr.To(10 * time.Second),
					TCPKeepAlive:           ptr.To(time.Minute),
					NoHappyEyeballs:        ptr.To(true),
					KeepAliveConnections:   ptr.To(100),
					KeepAliveTimeout:       ptr.To(90 * time.Second),
					DisableChunkedEncoding: ptr.To(true),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "http://10.0.0.1:80",
				OriginRequest: &cloudflare.OriginRequestConfig{
					ConnectTimeout:         &cloudflare.TunnelDuration{Duration: 30 * time.Second},
					TLSTimeout:             &cloudflare.TunnelDuration{Duration: 10 * time.Second},
					TCPKeepAlive:           &cloudflare.TunnelDuration{Duration: time.Minute},
					NoHappyEyeballs:        ptr.To(true),
					KeepAliveConnections:   ptr.To(100),
					KeepAliveTimeout:       &cloudflare.TunnelDuration{Duration: 90 * time.Second},
					DisableChunkedEncoding: ptr.To(true),
				},
			},
		}, {
			name: "direct no-tls-verify and http2-origin on https target",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "https://10.0.0.1:443",
					PathPrefix:    "/",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
					NoTLSVerify:   ptr.To(false),
					HTTP2Origin:   ptr.To(true),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "https://10.0.0.1:443",
				OriginRequest: &cloudflare.OriginRequestConfig{
					NoTLSVerify: ptr.To(false),
					Http2Origin: ptr.To(true),
				},
			},
		}, {
			name: "no-tls-verify applies to http target as well",
			args: args{
				ctx: context.Background(),
				exposure: exposure.Exposure{
					Hostname:      "ingress.example.com",
					ServiceTarget: "http://10.0.0.1:80",
					PathPrefix:    "/",
					PathType:      exposure.PathTypePrefix,
					IsDeleted:     false,
					NoTLSVerify:   ptr.To(true),
				},
			},
			want: &cloudflare.UnvalidatedIngressRule{
				Hostname: "ingress.example.com",
				Path:     "^/.*$",
				Service:  "http://10.0.0.1:80",
				OriginRequest: &cloudflare.OriginRequestConfig{
					NoTLSVerify: ptr.To(true),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fromExposureToCloudflareIngress(tt.args.ctx, tt.args.exposure)
			if (err != nil) != tt.wantErr {
				t.Errorf("fromExposureToCloudflareIngress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fromExposureToCloudflareIngress() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_buildCloudflarePathRegex(t *testing.T) {
	type args struct {
		path       string
		pathType   exposure.PathType
		matches    []string
		mismatches []string
	}
	tests := []args{
		{
			path:     "/api",
			pathType: exposure.PathTypePrefix,
			matches:  []string{"/api", "/api/v1/foo", "/api/"},
			mismatches: []string{
				"/apiary",
				"/assets/api-C-hkNku6.js",
				"/foo/api-bar.js",
				"/assets/foo/api/bar.js",
			},
		},
		{
			path:     "/",
			pathType: exposure.PathTypePrefix,
			matches:  []string{"/anything/at/all", "/"},
		},
		{
			path:     "/api/",
			pathType: exposure.PathTypePrefix,
			matches:  []string{"/api", "/api/v1"},
		},
		{
			path:       "/openapi.json",
			pathType:   exposure.PathTypeExact,
			matches:    []string{"/openapi.json"},
			mismatches: []string{"/openapiXjson", "/openapi.json/extra"},
		},
		{
			path:       "/api",
			pathType:   exposure.PathTypeExact,
			matches:    []string{"/api"},
			mismatches: []string{"/api/v1", "/apiary"},
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s path=%s", tt.pathType, tt.path), func(t *testing.T) {
			re := regexp.MustCompile(buildCloudflarePathRegex(tt.path, tt.pathType))
			for _, requestPath := range tt.matches {
				if !re.MatchString(requestPath) {
					t.Errorf("expected %q (regex %q) to match %q, it did not", tt.path, re.String(), requestPath)
				}
			}
			for _, requestPath := range tt.mismatches {
				if re.MatchString(requestPath) {
					t.Errorf("expected %q (regex %q) to NOT match %q, it did", tt.path, re.String(), requestPath)
				}
			}
		})
	}
}
