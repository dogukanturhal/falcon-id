// Vendored copy of github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 — the
// final v1 release (the line is frozen; upstream moved to an API-incompatible
// /v2). falcon-id pulls it transitively through github.com/authzed/grpcutil
// (SpiceDB client), which still pins v1.
//
// Why vendored: upstream v1.4.0 declares `go 1.14`, which forces Go's module
// graph to load its dependencies UN-pruned. One of those is a vestigial
// `// indirect` require on the monolithic google.golang.org/genproto whose
// go.mod transitively requires the entire cloud.google.com/go monorepo
// (~273 modules). go-grpc-middleware imports NOTHING from genproto (verified),
// so the require is dead weight — but under the go 1.14 directive it dragged
// 273 graph-only `.mod` fetches into every CI `go mod download`, making
// falcon-id builds ~25 min and Athens-failure-prone.
//
// Only change vs upstream v1.4.0: `go 1.14` -> `go 1.21` (enables graph
// pruning) and the dead `google.golang.org/genproto` require removed. No
// source changes. The grpc 1.29.1 floor is MVS-upgraded to the module's
// google.golang.org/grpc selection (>=1.80), which needs only the slim
// genproto submodules.
//
// Test files (*_test.go) and the testing/ fixtures are stripped — falcon-id
// never runs this module's tests (it's a `replace` target, excluded from
// `./...`), and testing/interceptor_suite.go carried a TLS test private key
// that has no business in this repo. Non-test source is a verbatim mirror of
// upstream v1.4.0.
module github.com/grpc-ecosystem/go-grpc-middleware

require (
	github.com/go-kit/log v0.1.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.3.3
	github.com/opentracing/opentracing-go v1.1.0
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.7.0
	go.uber.org/zap v1.18.1
	golang.org/x/net v0.0.0-20201021035429-f5854403a974
	golang.org/x/oauth2 v0.0.0-20180821212333-d2e6202438be
	golang.org/x/sys v0.0.0-20211025201205-69cdffdb9359 // indirect
	google.golang.org/grpc v1.29.1
)

go 1.21
