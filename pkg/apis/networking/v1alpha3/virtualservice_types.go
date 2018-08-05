/*
Copyright 2018 Bevyx.

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

package v1alpha3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A `VirtualService` defines a set of traffic routing rules to apply when a host is
// addressed. Each routing rule defines matching criteria for traffic of a specific
// protocol. If the traffic is matched, then it is sent to a named destination service
// (or subset/version of it) defined in the registry.
//
// The source of traffic can also be matched in a routing rule. This allows routing
// to be customized for specific client contexts.
//
// The following example on Kubernetes, routes all HTTP traffic by default to
// pods of the reviews service with label "version: v1". In addition,
// HTTP requests containing /wpcatalog/, /consumercatalog/ url prefixes will
// be rewritten to /newcatalog and sent to pods with label "version: v2".
//
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: reviews-route
// spec:
//   hosts:
//   - reviews.prod.svc.cluster.local
//   http:
//   - match:
//     - uri:
//         prefix: "/wpcatalog"
//     - uri:
//         prefix: "/consumercatalog"
//     rewrite:
//       uri: "/newcatalog"
//     route:
//     - destination:
//         host: reviews.prod.svc.cluster.local
//         subset: v2
//   - route:
//     - destination:
//         host: reviews.prod.svc.cluster.local
//         subset: v1
// ```
//
// A subset/version of a route destination is identified with a reference
// to a named service subset which must be declared in a corresponding
// `DestinationRule`.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: DestinationRule
// metadata:
//   name: reviews-destination
// spec:
//   host: reviews.prod.svc.cluster.local
//   subsets:
//   - name: v1
//     labels:
//       version: v1
//   - name: v2
//     labels:
//       version: v2
// ```
//
type VirtualServiceSpec struct {
	// REQUIRED. The destination hosts to which traffic is being sent. Could
	// be a DNS name with wildcard prefix or an IP address.  Depending on the
	// platform, short-names can also be used instead of a FQDN (i.e. has no
	// dots in the name). In such a scenario, the FQDN of the host would be
	// derived based on the underlying platform.
	//
	// **A host name can be defined by only one VirtualService**. A single
	// VirtualService can be used to describe traffic properties for multiple
	// HTTP and TCP ports.
	//
	// *Note for Kubernetes users*: When short names are used (e.g. "reviews"
	// instead of "reviews.default.svc.cluster.local"), Istio will interpret
	// the short name based on the namespace of the rule, not the service. A
	// rule in the "default" namespace containing a host "reviews will be
	// interpreted as "reviews.default.svc.cluster.local", irrespective of
	// the actual namespace associated with the reviews service. _To avoid
	// potential misconfigurations, it is recommended to always use fully
	// qualified domain names over short names._
	//
	// The hosts field applies to both HTTP and TCP services. Service inside
	// the mesh, i.e., those found in the service registry, must always be
	// referred to using their alphanumeric names. IP addresses are allowed
	// only for services defined via the Gateway.
	Hosts []string `json:"hosts,omitempty"`
	// The names of gateways and sidecars that should apply these routes. A
	// single VirtualService is used for sidecars inside the mesh as well as
	// for one or more gateways. The selection condition imposed by this
	// field can be overridden using the source field in the match conditions
	// of protocol-specific routes. The reserved word `mesh` is used to imply
	// all the sidecars in the mesh. When this field is omitted, the default
	// gateway (`mesh`) will be used, which would apply the rule to all
	// sidecars in the mesh. If a list of gateway names is provided, the
	// rules will apply only to the gateways. To apply the rules to both
	// gateways and sidecars, specify `mesh` as one of the gateway names.
	Gateways []string `json:"gateways,omitempty"`
	// An ordered list of route rules for HTTP traffic. HTTP routes will be
	// applied to platform service ports named 'http-*'/'http2-*'/'grpc-*', gateway
	// ports with protocol HTTP/HTTP2/GRPC/ TLS-terminated-HTTPS and service
	// entry ports using HTTP/HTTP2/GRPC protocols.  The first rule matching
	// an incoming request is used.
	Http []HTTPRoute `json:"http,omitempty"`
	// An ordered list of route rule for non-terminated TLS & HTTPS
	// traffic. Routing is typically performed using the SNI value presented
	// by the ClientHello message. TLS routes will be applied to platform
	// service ports named 'https-*', 'tls-*', unterminated gateway ports using
	// HTTPS/TLS protocols (i.e. with "passthrough" TLS mode) and service
	// entry ports using HTTPS/TLS protocols.  The first rule matching an
	// incoming request is used.  NOTE: Traffic 'https-*' or 'tls-*' ports
	// without associated virtual service will be treated as opaque TCP
	// traffic.
	Tls []TLSRoute `json:"tls,omitempty"`
	// An ordered list of route rules for opaque TCP traffic. TCP routes will
	// be applied to any port that is not a HTTP or TLS port. The first rule
	// matching an incoming request is used.
	Tcp []TCPRoute `json:"tcp,omitempty"`
}

// Destination indicates the network addressable service to which the
// request/connection will be sent after processing a routing rule. The
// destination.host should unambiguously refer to a service in the service
// registry. Istio's service registry is composed of all the services found
// in the platform's service registry (e.g., Kubernetes services, Consul
// services), as well as services declared through the
// [ServiceEntry](#ServiceEntry) resource.
//
// *Note for Kubernetes users*: When short names are used (e.g. "reviews"
// instead of "reviews.default.svc.cluster.local"), Istio will interpret
// the short name based on the namespace of the rule, not the service. A
// rule in the "default" namespace containing a host "reviews will be
// interpreted as "reviews.default.svc.cluster.local", irrespective of the
// actual namespace associated with the reviews service. _To avoid potential
// misconfigurations, it is recommended to always use fully qualified
// domain names over short names._
//
// The following Kubernetes example routes all traffic by default to pods
// of the reviews service with label "version: v1" (i.e., subset v1), and
// some to subset v2, in a kubernetes environment.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: reviews-route
//   namespace: foo
// spec:
//   hosts:
//   - reviews # interpreted as reviews.foo.svc.cluster.local
//   http:
//   - match:
//     - uri:
//         prefix: "/wpcatalog"
//     - uri:
//         prefix: "/consumercatalog"
//     rewrite:
//       uri: "/newcatalog"
//     route:
//     - destination:
//         host: reviews # interpreted as reviews.foo.svc.cluster.local
//         subset: v2
//   - route:
//     - destination:
//         host: reviews # interpreted as reviews.foo.svc.cluster.local
//         subset: v1
// ```
//
// And the associated DestinationRule
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: DestinationRule
// metadata:
//   name: reviews-destination
//   namespace: foo
// spec:
//   host: reviews # interpreted as reviews.foo.svc.cluster.local
//   subsets:
//   - name: v1
//     labels:
//       version: v1
//   - name: v2
//     labels:
//       version: v2
// ```
//
// The following VirtualService sets a timeout of 5s for all calls to
// productpage.prod.svc.cluster.local service in Kubernetes. Notice that
// there are no subsets defined in this rule. Istio will fetch all
// instances of productpage.prod.svc.cluster.local service from the service
// registry and populate the sidecar's load balancing pool. Also, notice
// that this rule is set in the istio-system namespace but uses the fully
// qualified domain name of the productpage service,
// productpage.prod.svc.cluster.local. Therefore the rule's namespace does
// not have an impact in resolving the name of the productpage service.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: my-productpage-rule
//   namespace: istio-system
// spec:
//   hosts:
//   - productpage.prod.svc.cluster.local # ignores rule namespace
//   http:
//   - timeout: 5s
//     route:
//     - destination:
//         host: productpage.prod.svc.cluster.local
// ```
//
// To control routing for traffic bound to services outside the mesh, external
// services must first be added to Istio's internal service registry using the
// ServiceEntry resource. VirtualServices can then be defined to control traffic
// bound to these external services. For example, the following rules define a
// Service for wikipedia.org and set a timeout of 5s for http requests.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: ServiceEntry
// metadata:
//   name: external-svc-wikipedia
// spec:
//   hosts:
//   - wikipedia.org
//   location: MESH_EXTERNAL
//   ports:
//   - number: 80
//     name: example-http
//     protocol: HTTP
//   resolution: DNS
//
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: my-wiki-rule
// spec:
//   hosts:
//   - wikipedia.org
//   http:
//   - timeout: 5s
//     route:
//     - destination:
//         host: wikipedia.org
// ```
type Destination struct {
	// REQUIRED. The name of a service from the service registry. Service
	// names are looked up from the platform's service registry (e.g.,
	// Kubernetes services, Consul services, etc.) and from the hosts
	// declared by [ServiceEntry](#ServiceEntry). Traffic forwarded to
	// destinations that are not found in either of the two, will be dropped.
	//
	// *Note for Kubernetes users*: When short names are used (e.g. "reviews"
	// instead of "reviews.default.svc.cluster.local"), Istio will interpret
	// the short name based on the namespace of the rule, not the service. A
	// rule in the "default" namespace containing a host "reviews will be
	// interpreted as "reviews.default.svc.cluster.local", irrespective of
	// the actual namespace associated with the reviews service. _To avoid
	// potential misconfigurations, it is recommended to always use fully
	// qualified domain names over short names._
	Host string `json:"host,omitempty"`
	// The name of a subset within the service. Applicable only to services
	// within the mesh. The subset must be defined in a corresponding
	// DestinationRule.
	Subset string `json:"subset,omitempty"`
	// Specifies the port on the host that is being addressed. If a service
	// exposes only a single port it is not required to explicitly select the
	// port.
	Port *PortSelector `json:"port,omitempty"`
}

// Describes match conditions and actions for routing HTTP/1.1, HTTP2, and
// gRPC traffic. See VirtualService for usage examples.
type HTTPRoute struct {
	// Match conditions to be satisfied for the rule to be
	// activated. All conditions inside a single match block have AND
	// semantics, while the list of match blocks have OR semantics. The rule
	// is matched if any one of the match blocks succeed.
	Match []HTTPMatchRequest `json:"match,omitempty"`
	// A http rule can either redirect or forward (default) traffic. The
	// forwarding target can be one of several versions of a service (see
	// glossary in beginning of document). Weights associated with the
	// service version determine the proportion of traffic it receives.
	Route []DestinationWeight `json:"route,omitempty"`
	// A http rule can either redirect or forward (default) traffic. If
	// traffic passthrough option is specified in the rule,
	// route/redirect will be ignored. The redirect primitive can be used to
	// send a HTTP 301 redirect to a different URI or Authority.
	Redirect *HTTPRedirect `json:"redirect,omitempty"`
	// Rewrite HTTP URIs and Authority headers. Rewrite cannot be used with
	// Redirect primitive. Rewrite will be performed before forwarding.
	Rewrite *HTTPRewrite `json:"rewrite,omitempty"`
	// Deprecated. Websocket upgrades are done automatically starting from Istio 1.0.
	// $hide_from_docs
	WebsocketUpgrade bool `json:"websocket_upgrade,omitempty"`
	// Timeout for HTTP requests.
	Timeout string `json:"timeout,omitempty"`
	// Retry policy for HTTP requests.
	Retries *HTTPRetry `json:"retries,omitempty"`
	// Fault injection policy to apply on HTTP traffic at the client side.
	// Note that timeouts or retries will not be enabled when faults are
	// enabled on the client side.
	Fault *HTTPFaultInjection `json:"fault,omitempty"`
	// Mirror HTTP traffic to a another destination in addition to forwarding
	// the requests to the intended destination. Mirrored traffic is on a
	// bestHTTPFaultInjection `json:"fault,omitempty"`
	// Mirror HTTP traffic to a another destination in addition to forwarding
	// the requests to the intended destination. Mirrored traffic is on a
	// best effort basis where the sidecar/gateway will not wait for the
	// mirrored cluster to respond before returning the response from the
	// original destination.  Statistics will be generated for the mirrored
	// destination.
	Mirror *Destination `json:"mirror,omitempty"`
	// Cross-Origin Resource Sharing policy (CORS). Refer to
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
	// for further details about cross origin resource sharing.
	CorsPolicy *CorsPolicy `json:"cors_policy,omitempty"`
	// Additional HTTP headers to add before forwarding a request to the
	// destination service.
	AppendHeaders map[string]string `json:"append_headers,omitempty"`
	// Http headers to remove before returning the response to the caller
	// $hide_from_docs
	RemoveResponseHeaders []string `json:"remove_response_headers,omitempty"`
}

// Describes match conditions and actions for routing unterminated TLS
// traffic (TLS/HTTPS) The following routing rule forwards unterminated TLS
// traffic arriving at port 443 of gateway called "mygateway" to internal
// services in the mesh based on the SNI value.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: bookinfo-sni
// spec:
//   hosts:
//   - "*.bookinfo.com"
//   gateways:
//   - mygateway
//   tls:
//   - match:
//     - port: 443
//       sniHosts:
//       - login.bookinfo.com
//     route:
//     - destination:
//         host: login.prod.svc.cluster.local
//   - match:
//     - port: 443
//       sniHosts:
//       - reviews.bookinfo.com
//     route:
//     - destination:
//         host: reviews.prod.svc.cluster.local
// ```
type TLSRoute struct {
	// REQUIRED. Match conditions to be satisfied for the rule to be
	// activated. All conditions inside a single match block have AND
	// semantics, while the list of match blocks have OR semantics. The rule
	// is matched if any one of the match blocks succeed.
	Match []TLSMatchAttributes `json:"match,omitempty"`
	// The destination to which the connection should be forwarded to.
	// Currently, only one destination is allowed for TLS services. When TCP
	// weighted routing support is introduced in Envoy, multiple destinations
	// with weights can be specified.
	Route []DestinationWeight `json:"route,omitempty"`
}

// Describes match conditions and actions for routing TCP traffic. The
// following routing rule forwards traffic arriving at port 27017 for
// mongo.prod.svc.cluster.local to another Mongo server on port 5555.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: bookinfo-Mongo
// spec:
//   hosts:
//   - mongo.prod.svc.cluster.local
//   tcp:
//   - match:
//     - port: 27017
//     route:
//     - destination:
//         host: mongo.backup.svc.cluster.local
//         port:
//           number: 5555
// ```
type TCPRoute struct {
	// Match conditions to be satisfied for the rule to be
	// activated. All conditions inside a single match block have AND
	// semantics, while the list of match blocks have OR semantics. The rule
	// is matched if any one of the match blocks succeed.
	Match []L4MatchAttributes `json:"match,omitempty"`
	// The destination to which the connection should be forwarded to.
	// Currently, only one destination is allowed for TCP services. When TCP
	// weighted routing support is introduced in Envoy, multiple destinations
	// with weights can be specified.
	Route []DestinationWeight `json:"route,omitempty"`
}

// HttpMatchRequest specifies a set of criterion to be met in order for the
// rule to be applied to the HTTP request. For example, the following
// restricts the rule to match only requests where the URL path
// starts with /ratings/v2/ and the request contains a custom `end-user` header
// with value `jason`.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: ratings-route
// spec:
//   hosts:
//   - ratings.prod.svc.cluster.local
//   http:
//   - match:
//     - headers:
//         end-user:
//           exact: jason
//       uri:
//         prefix: "/ratings/v2/"
//     route:
//     - destination:
//         host: ratings.prod.svc.cluster.local
// ```
//
// HTTPMatchRequest CANNOT be empty.
type HTTPMatchRequest struct {
	// URI to match
	// values are case-sensitive and formatted as follows:
	//
	// - `exact: "value"` for exact string match
	//
	// - `prefix: "value"` for prefix-based match
	//
	// - `regex: "value"` for ECMAscript style regex-based match
	//
	Uri *StringMatch `json:"uri,omitempty"`
	// URI Scheme
	// values are case-sensitive and formatted as follows:
	//
	// - `exact: "value"` for exact string match
	//
	// - `prefix: "value"` for prefix-based match
	//
	// - `regex: "value"` for ECMAscript style regex-based match
	//
	Scheme *StringMatch `json:"scheme,omitempty"`
	// HTTP Method
	// values are case-sensitive and formatted as follows:
	//
	// - `exact: "value"` for exact string match
	//
	// - `prefix: "value"` for prefix-based match
	//
	// - `regex: "value"` for ECMAscript style regex-based match
	//
	Method *StringMatch `json:"method,omitempty"`
	// HTTP Authority
	// values are case-sensitive and formatted as follows:
	//
	// - `exact: "value"` for exact string match
	//
	// - `prefix: "value"` for prefix-based match
	//
	// - `regex: "value"` for ECMAscript style regex-based match
	//
	Authority *StringMatch `json:"authority,omitempty"`
	// The header keys must be lowercase and use hyphen as the separator,
	// e.g. _x-request-id_.
	//
	// Header values are case-sensitive and formatted as follows:
	//
	// - `exact: "value"` for exact string match
	//
	// - `prefix: "value"` for prefix-based match
	//
	// - `regex: "value"` for ECMAscript style regex-based match
	//
	// **Note:** The keys `uri`, `scheme`, `method`, and `authority` will be ignored.
	Headers map[string]StringMatch `json:"headers,omitempty"`
	// Specifies the ports on the host that is being addressed. Many services
	// only expose a single port or label ports with the protocols they support,
	// in these cases it is not required to explicitly select the port.
	Port uint32 `json:"port,omitempty"`
	// One or more labels that constrain the applicability of a rule to
	// workloads with the given labels. If the VirtualService has a list of
	// gateways specified at the top, it should include the reserved gateway
	// `mesh` in order for this field to be applicable.
	SourceLabels map[string]string `json:"source_labels,omitempty"`
	// Names of gateways where the rule should be applied to. Gateway names
	// at the top of the VirtualService (if any) are overridden. The gateway match is
	// independent of sourceLabels.
	Gateways []string `json:"gateways,omitempty"`
}

// Each routing rule is associated with one or more service versions (see
// glossary in beginning of document). Weights associated with the version
// determine the proportion of traffic it receives. For example, the
// following rule will route 25% of traffic for the "reviews" service to
// instances with the "v2" tag and the remaining traffic (i.e., 75%) to
// "v1".
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: reviews-route
// spec:
//   hosts:
//   - reviews.prod.svc.cluster.local
//   http:
//   - route:
//     - destination:
//         host: reviews.prod.svc.cluster.local
//         subset: v2
//       weight: 25
//     - destination:
//         host: reviews.prod.svc.cluster.local
//         subset: v1
//       weight: 75
// ```
//
// And the associated DestinationRule
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: DestinationRule
// metadata:
//   name: reviews-destination
// spec:
//   host: reviews.prod.svc.cluster.local
//   subsets:
//   - name: v1
//     labels:
//       version: v1
//   - name: v2
//     labels:
//       version: v2
// ```
//
// Traffic can also be split across two entirely different services without
// having to define new subsets. For example, the following rule forwards 25% of
// traffic to reviews.com to dev.reviews.com
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: reviews-route-two-domains
// spec:
//   hosts:
//   - reviews.com
//   http:
//   - route:
//     - destination:
//         host: dev.reviews.com
//       weight: 25
//     - destination:
//         host: reviews.com
//       weight: 75
// ```
type DestinationWeight struct {
	// REQUIRED. Destination uniquely identifies the instances of a service
	// to which the request/connection should be forwarded to.
	Destination Destination `json:"destination,omitempty"`
	// REQUIRED. The proportion of traffic to be forwarded to the service
	// version. (0-100). Sum of weights across destinations SHOULD BE == 100.
	// If there is only one destination in a rule, the weight value is assumed to
	// be 100.
	Weight int32 `json:"weight,omitempty"`
}

// L4 connection match attributes. Note that L4 connection matching support
// is incomplete.
type L4MatchAttributes struct {
	// IPv4 or IPv6 ip addresses of destination with optional subnet.  E.g.,
	// a.b.c.d/xx form or just a.b.c.d.
	DestinationSubnets []string `json:"destination_subnets,omitempty"`
	// Specifies the port on the host that is being addressed. Many services
	// only expose a single port or label ports with the protocols they support,
	// in these cases it is not required to explicitly select the port.
	Port uint32 `json:"port,omitempty"`
	// IPv4 or IPv6 ip address of source with optional subnet. E.g., a.b.c.d/xx
	// form or just a.b.c.d
	// $hide_from_docs
	SourceSubnet string `json:"source_subnet,omitempty"`
	// One or more labels that constrain the applicability of a rule to
	// workloads with the given labels. If the VirtualService has a list of
	// gateways specified at the top, it should include the reserved gateway
	// `mesh` in order for this field to be applicable.
	SourceLabels map[string]string `json:"source_labels,omitempty"`
	// Names of gateways where the rule should be applied to. Gateway names
	// at the top of the VirtualService (if any) are overridden. The gateway
	// match is independent of sourceLabels.
	Gateways []string `json:"gateways,omitempty"`
}

// TLS connection match attributes.
type TLSMatchAttributes struct {
	// REQUIRED. SNI (server name indicator) to match on. Wildcard prefixes
	// can be used in the SNI value. E.g., *.com will match foo.example.com
	// as well as example.com.
	SniHosts []string `json:"sni_hosts,omitempty"`
	// IPv4 or IPv6 ip addresses of destination with optional subnet.  E.g.,
	// a.b.c.d/xx form or just a.b.c.d.
	DestinationSubnets []string `json:"destination_subnets,omitempty"`
	// Specifies the port on the host that is being addressed. Many services
	// only expose a single port or label ports with the protocols they
	// support, in these cases it is not required to explicitly select the
	// port.
	Port uint32 `json:"port,omitempty"`
	// IPv4 or IPv6 ip address of source with optional subnet. E.g., a.b.c.d/xx
	// form or just a.b.c.d
	// $hide_from_docs
	SourceSubnet string `json:"source_subnet,omitempty"`
	// One or more labels that constrain the applicability of a rule to
	// workloads with the given labels. If the VirtualService has a list of
	// gateways specified at the top, it should include the reserved gateway
	// `mesh` in order for this field to be applicable.
	SourceLabels map[string]string `json:"source_labels,omitempty"`
	// Names of gateways where the rule should be applied to. Gateway names
	// at the top of the VirtualService (if any) are overridden. The gateway
	// match is independent of sourceLabels.
	Gateways []string `json:"gateways,omitempty"`
}

// HTTPRedirect can be used to send a 301 redirect response to the caller,
// where the Authority/Host and the URI in the response can be swapped with
// the specified values. For example, the following rule redirects
// requests for /v1/getProductRatings API on the ratings service to
// /v1/bookRatings provided by the bookratings service.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: ratings-route
// spec:
//   hosts:
//   - ratings.prod.svc.cluster.local
//   http:
//   - match:
//     - uri:
//         exact: /v1/getProductRatings
//   redirect:
//     uri: /v1/bookRatings
//     authority: newratings.default.svc.cluster.local
//   ...
// ```
type HTTPRedirect struct {
	// On a redirect, overwrite the Path portion of the URL with this
	// value. Note that the entire path will be replaced, irrespective of the
	// request URI being matched as an exact path or prefix.
	Uri string `json:"uri,omitempty"`
	// On a redirect, overwrite the Authority/Host portion of the URL with
	// this value.
	Authority string `json:"authority,omitempty"`
}

// HTTPRewrite can be used to rewrite specific parts of a HTTP request
// before forwarding the request to the destination. Rewrite primitive can
// be used only with the DestinationWeights. The following example
// demonstrates how to rewrite the URL prefix for api call (/ratings) to
// ratings service before making the actual API call.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: ratings-route
// spec:
//   hosts:
//   - ratings.prod.svc.cluster.local
//   http:
//   - match:
//     - uri:
//         prefix: /ratings
//     rewrite:
//       uri: /v1/bookRatings
//     route:
//     - destination:
//         host: ratings.prod.svc.cluster.local
//         subset: v1
// ```
//
type HTTPRewrite struct {
	// rewrite the path (or the prefix) portion of the URI with this
	// value. If the original URI was matched based on prefix, the value
	// provided in this field will replace the corresponding matched prefix.
	Uri string `json:"uri,omitempty"`
	// rewrite the Authority/Host header with this value.
	Authority string `json:"authority,omitempty"`
}

// Describes how to match a given string in HTTP headers. Match is
// case-sensitive.
type StringMatch struct {
	// Specified exactly one of the fields below.

	// exact string match
	Exact string `json:"exact,omitempty"`

	// prefix-based match
	Prefix string `json:"prefix,omitempty"`

	// ECMAscript style regex-based match
	Regex string `json:"regex,omitempty"`
}

// Describes the retry policy to use when a HTTP request fails. For
// example, the following rule sets the maximum number of retries to 3 when
// calling ratings:v1 service, with a 2s timeout per retry attempt.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: ratings-route
// spec:
//   hosts:
//   - ratings.prod.svc.cluster.local
//   http:
//   - route:
//     - destination:
//         host: ratings.prod.svc.cluster.local
//         subset: v1
//     retries:
//       attempts: 3
//       perTryTimeout: 2s
// ```
//
type HTTPRetry struct {
	// REQUIRED. Number of retries for a given request. The interval
	// between retries will be determined automatically (25ms+). Actual
	// number of retries attempted depends on the httpReqTimeout.
	Attempts int32 `json:"attempts,omitempty"`
	// Timeout per retry attempt for a given request. format: 1h/1m/1s/1ms. MUST BE >=1ms.
	PerTryTimeout string `json:"per_try_timeout,omitempty"`
}

// Describes the Cross-Origin Resource Sharing (CORS) policy, for a given
// service. Refer to
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
// for further details about cross origin resource sharing. For example,
// the following rule restricts cross origin requests to those originating
// from example.com domain using HTTP POST/GET, and sets the
// Access-Control-Allow-Credentials header to false. In addition, it only
// exposes X-Foo-bar header and sets an expiry period of 1 day.
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: ratings-route
// spec:
//   hosts:
//   - ratings.prod.svc.cluster.local
//   http:
//   - route:
//     - destination:
//         host: ratings.prod.svc.cluster.local
//         subset: v1
//     corsPolicy:
//       allowOrigin:
//       - example.com
//       allowMethods:
//       - POST
//       - GET
//       allowCredentials: false
//       allowHeaders:
//       - X-Foo-Bar
//       maxAge: "1d"
// ```
//
type CorsPolicy struct {
	// The list of origins that are allowed to perform CORS requests. The
	// content will be serialized into the Access-Control-Allow-Origin
	// header. Wildcard * will allow all origins.
	AllowOrigin []string `json:"allow_origin,omitempty"`
	// List of HTTP methods allowed to access the resource. The content will
	// be serialized into the Access-Control-Allow-Methods header.
	AllowMethods []string `json:"allow_methods,omitempty"`
	// List of HTTP headers that can be used when requesting the
	// resource. Serialized to Access-Control-Allow-Headers header.
	AllowHeaders []string `json:"allow_headers,omitempty"`
	// A white list of HTTP headers that the browsers are allowed to
	// access. Serialized into Access-Control-Expose-Headers header.
	ExposeHeaders []string `json:"expose_headers,omitempty"`
	// Specifies how long the the results of a preflight request can be
	// cached. Translates to the Access-Control-Max-Age header.
	MaxAge string `json:"max_age,omitempty"`
	// Indicates whether the caller is allowed to send the actual request
	// (not the preflight) using credentials. Translates to
	// Access-Control-Allow-Credentials header.
	AllowCredentials bool `json:"allow_credentials,omitempty"`
}

// HTTPFaultInjection can be used to specify one or more faults to inject
// while forwarding http requests to the destination specified in a route.
// Fault specification is part of a VirtualService rule. Faults include
// aborting the Http request from downstream service, and/or delaying
// proxying of requests. A fault rule MUST HAVE delay or abort or both.
//
// *Note:* Delay and abort faults are independent of one another, even if
// both are specified simultaneously.
type HTTPFaultInjection struct {
	// Delay requests before forwarding, emulating various failures such as
	// network issues, overloaded upstream service, etc.
	Delay *HTTPFaultInjection_Delay `json:"delay,omitempty"`
	// Abort Http request attempts and return error codes back to downstream
	// service, giving the impression that the upstream service is faulty.
	Abort *HTTPFaultInjection_Abort `json:"abort,omitempty"`
}

// Delay specification is used to inject latency into the request
// forwarding path. The following example will introduce a 5 second delay
// in 10% of the requests to the "v1" version of the "reviews"
// service from all pods with label env: prod
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: reviews-route
// spec:
//   hosts:
//   - reviews.prod.svc.cluster.local
//   http:
//   - match:
//     - sourceLabels:
//         env: prod
//     route:
//     - destination:
//         host: reviews.prod.svc.cluster.local
//         subset: v1
//     fault:
//       delay:
//         percent: 10
//         fixedDelay: 5s
// ```
//
// The _fixedDelay_ field is used to indicate the amount of delay in
// seconds. An optional _percent_ field, a value between 0 and 100, can
// be used to only delay a certain percentage of requests. If left
// unspecified, all request will be delayed.
type HTTPFaultInjection_Delay struct {
	// Percentage of requests on which the delay will be injected (0-100).
	Percent int32 `json:"percent,omitempty"`

	// Specified exactly one of the fields below.

	// REQUIRED. Add a fixed delay before forwarding the request. Format:
	// 1h/1m/1s/1ms. MUST be >=1ms.
	FixedDelay string `json:"fixedDelay,omitempty"`

	// (-- Add a delay (based on an exponential function) before forwarding
	// the request. mean delay needed to derive the exponential delay
	// values --)
	ExponentialDelay string `json:"exponentialDelay,omitempty"`
}

// Abort specification is used to prematurely abort a request with a
// pre-specified error code. The following example will return an HTTP
// 400 error code for 10% of the requests to the "ratings" service "v1".
//
// ```yaml
// apiVersion: networking.istio.io/v1alpha3
// kind: VirtualService
// metadata:
//   name: ratings-route
// spec:
//   hosts:
//   - ratings.prod.svc.cluster.local
//   http:
//   - route:
//     - destination:
//         host: ratings.prod.svc.cluster.local
//         subset: v1
//     fault:
//       abort:
//         percent: 10
//         httpStatus: 400
// ```
//
// The _httpStatus_ field is used to indicate the HTTP status code to
// return to the caller. The optional _percent_ field, a value between 0
// and 100, is used to only abort a certain percentage of requests. If
// not specified, all requests are aborted.
type HTTPFaultInjection_Abort struct {
	// Percentage of requests to be aborted with the error code provided (0-100).
	Percent int32 `json:"percent,omitempty"`

	// REQUIRED. Specified exactly one of the fields below.

	// HTTP status code to use to abort the Http request.
	HttpStatus int32 `json:"httpStatus,omitempty"`

	// GRCP status code to use to abort the GRCP request.
	GrpcStatus string `json:"grpcStatus,omitempty"`

	// HTTP2 error code to use to abort the Http2 request.
	Http2Error string `json:"http2Error,omitempty"`
}

// PortSelector specifies the number of a port to be used for
// matching or selection for final routing.
type PortSelector struct {
	// Choose one of the fields below.

	// Valid port number
	Number uint32 `json:"number,omitempty"`

	// Valid port name
	Name string `json:"name,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualService is the Schema for the VirtualServices API
// +k8s:openapi-gen=true
type VirtualService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec VirtualServiceSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualServiceList contains a list of VirtualService
type VirtualServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualService `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualService{}, &VirtualServiceList{})
}
