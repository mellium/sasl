// Copyright 2016 The Mellium Contributors.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"strconv"
	"testing"
)

// saslStep is from the perspective of a client, challenge is issued by the
// server and resp is the clients response (the first challenge will generally
// be empty because SASL is a client-first protocol).
type saslStep struct {
	challenge []byte
	resp      []byte
	more      bool
	clientErr bool
	serverErr bool
}

type saslTest struct {
	mechanism  Mechanism
	clientOpts []Option
	serverOpts []Option
	perm       func(*Negotiator) bool
	steps      []saslStep
	skipClient bool
	skipServer bool
}

func getStepName(n *Negotiator) string {
	switch n.State() & StepMask {
	case Initial:
		return "Initial"
	case AuthTextSent:
		return "AuthTextSent"
	case ResponseSent:
		return "ResponseSent"
	case ValidServerResponse:
		return "ValidServerResponse"
	default:
		panic("Step part of state byte apparently has too many bits")
	}
}

var (
	plainResp       = []byte("Ursel\x00Kurt\x00xipj3plmq")
	testNonce       = []byte("fyko+d2lbbFgONRv9qkxdawL")
	plainClientOpts = []Option{Credentials(func() ([]byte, []byte, []byte) {
		return []byte("Kurt"), []byte("xipj3plmq"), []byte("Ursel")
	})}
)

func acceptAll(_ *Negotiator) bool {
	return true
}

var saslTestCases = [...]saslTest{
	0: {
		skipServer: true,
		mechanism:  plain,
		clientOpts: plainClientOpts,
		steps: []saslStep{
			{resp: plainResp, more: false},
			{challenge: nil, resp: nil, clientErr: true, more: false},
		},
	},
	1: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-1", sha1.New),
		clientOpts: []Option{Credentials(func() ([]byte, []byte, []byte) {
			return []byte("user"), []byte("pencil"), []byte{}
		})},
		steps: []saslStep{
			{
				resp: []byte(`n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL`),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096`),
				resp:      []byte(`c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=`),
				more:      true,
			},
			{
				challenge: []byte(`v=rmF9pqV8S7suAoZWja4dJRkFsKQ=`),
				resp:      nil,
				more:      false,
			},
		},
	},
	2: {
		skipServer: true,
		// Mechanism is not SCRAM-SHA-1-PLUS, but has connstate and remote mechanisms.
		mechanism: scram("SCRAM-SHA-1", sha1.New),
		clientOpts: []Option{
			Credentials(func() ([]byte, []byte, []byte) {
				return []byte("user"), []byte("pencil"), []byte{}
			}),
			RemoteMechanisms("SCRAM-SHA-1-PLUS", "SCRAM-SHA-1"),
			TLSState(tls.ConnectionState{TLSUnique: []byte{0, 1, 2, 3, 4}}),
		},
		steps: []saslStep{
			{
				resp: []byte(`n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL`),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096`),
				resp:      []byte(`c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=`),
				more:      true,
			},
			{
				challenge: []byte(`v=rmF9pqV8S7suAoZWja4dJRkFsKQ=`),
				resp:      nil,
				more:      false,
			},
		},
	},
	3: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-1-PLUS", sha1.New),
		clientOpts: []Option{
			Credentials(func() ([]byte, []byte, []byte) {
				return []byte("user"), []byte("pencil"), []byte{}
			}),
			RemoteMechanisms("SCRAM-SHA-1-PLUS"),
			TLSState(tls.ConnectionState{TLSUnique: []byte{0, 1, 2, 3, 4}}),
		},
		steps: []saslStep{
			{
				resp: []byte(`p=tls-unique,,n=user,r=fyko+d2lbbFgONRv9qkxdawL`),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL16090868851744577,s=QSXCR+Q6sek8bf92,i=4096`),
				resp:      []byte(`c=cD10bHMtdW5pcXVlLCwAAQIDBA==,r=fyko+d2lbbFgONRv9qkxdawL16090868851744577,p=kD6Wfe1kGICYN08YH7oONG2Enb0=`),
				more:      true,
			},
			{
				challenge: []byte(`v=QI0Ihj/QJv+VSyezLtd/d5PrYy0=`),
				resp:      nil,
				more:      false,
			},
		},
	},
	4: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-256", sha256.New),
		clientOpts: []Option{Credentials(func() ([]byte, []byte, []byte) {
			return []byte("user"), []byte("pencil"), []byte{}
		})},
		steps: []saslStep{
			{
				resp: []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`),
				resp:      []byte(`c=biws,r=fyko+d2lbbFgONRv9qkxdawL%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=2FUSN0pPcS7P8hBhsxBJOiUDbRoW4KVNGZT0LxVnSek=`),
				more:      true,
			},
			{
				challenge: []byte(`v=zJZjsVp2g+W9jd01vgbsshippfH1sM0tLdBvs+e3DF4=`),
				resp:      nil,
				more:      false,
			},
		},
	},
	5: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-256-PLUS", sha256.New),
		clientOpts: []Option{
			Credentials(func() ([]byte, []byte, []byte) {
				return []byte("user"), []byte("pencil"), []byte("admin")
			}),
			RemoteMechanisms("SCRAM-SOMETHING", "SCRAM-SHA-256-PLUS"),
			TLSState(tls.ConnectionState{TLSUnique: []byte{0, 1, 2, 3, 4}}),
		},
		steps: []saslStep{
			{
				resp: []byte("p=tls-unique,a=admin,n=user,r=fyko+d2lbbFgONRv9qkxdawL"),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`),
				resp:      []byte(`c=cD10bHMtdW5pcXVlLGE9YWRtaW4sAAECAwQ=,r=fyko+d2lbbFgONRv9qkxdawL,p=USNVS9hYD1JWfBOQwzc8o/9vFPQ7kA4CKsocmko/8yU=`),
				more:      true,
			},
			{
				challenge: []byte(`v=zjC1aKz20rqp7P92qtiJD1+gihbP5dKzIUFlBWgOuss=`),
				resp:      nil,
				more:      false,
			},
		},
	},
	6: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-1-PLUS", sha1.New),
		clientOpts: []Option{
			Credentials(func() ([]byte, []byte, []byte) {
				return []byte(",=,="), []byte("password"), []byte{}
			}),
			RemoteMechanisms("SCRAM-SHA-1-PLUS"),
			TLSState(tls.ConnectionState{TLSUnique: []byte("finishedmessage")}),
		},
		steps: []saslStep{
			{
				resp: []byte("p=tls-unique,,n==2C=3D=2C=3D,r=fyko+d2lbbFgONRv9qkxdawL"),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawLtheirnonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`),
				resp:      []byte(`c=cD10bHMtdW5pcXVlLCxmaW5pc2hlZG1lc3NhZ2U=,r=fyko+d2lbbFgONRv9qkxdawLtheirnonce,p=8t6BJnSAd7Vi+mGZEi+Oqwci11c=`),
				more:      true,
			},
			{
				challenge: []byte(`v=8IDvl31piL1lkn6XLCqqFVS4EJM=`),
				resp:      nil,
				more:      false,
			},
		},
	},
	7: {
		skipClient: true,
		mechanism:  plain,
		perm:       acceptAll,
		steps: []saslStep{
			{resp: []byte("\x00Ursel\x00Kurt\x00xipj3plmq"), serverErr: true, more: false},
		},
	},
	8: {
		mechanism: plain,
		perm: func(n *Negotiator) bool {
			user, pass, ident := n.Credentials()
			switch {
			case string(user) != "Kurt":
				return false
			case string(pass) != "xipj3plmq":
				return false
			case string(ident) != "Ursel":
				return false
			}
			return true
		},
		clientOpts: plainClientOpts,
		steps: []saslStep{
			{resp: plainResp, more: false},
		},
	},
	9: {
		mechanism: plain,
		perm: func(n *Negotiator) bool {
			user, _, _ := n.Credentials()
			return string(user) == "FAIL"
		},
		clientOpts: plainClientOpts,
		steps: []saslStep{
			{resp: plainResp, serverErr: true, more: false},
		},
	},
	10: {
		mechanism: plain,
		perm: func(n *Negotiator) bool {
			_, pass, _ := n.Credentials()
			return string(pass) == "FAIL"
		},
		clientOpts: plainClientOpts,
		steps: []saslStep{
			{resp: plainResp, serverErr: true, more: false},
		},
	},
	11: {
		mechanism: plain,
		perm: func(n *Negotiator) bool {
			_, _, ident := n.Credentials()
			return string(ident) == "FAIL"
		},
		clientOpts: plainClientOpts,
		steps: []saslStep{
			{resp: plainResp, serverErr: true, more: false},
		},
	},
	12: {
		mechanism:  plain,
		clientOpts: plainClientOpts,
		steps: []saslStep{
			{resp: plainResp, serverErr: true, more: false},
		},
	},
	13: {
		skipClient: true,
		mechanism:  scram("", nil),
		perm:       acceptAll,
		steps: []saslStep{
			{serverErr: true, more: false},
		},
	},
	14: {
		skipClient: true,
		mechanism:  scram("", nil),
		perm:       acceptAll,
		steps: []saslStep{
			{resp: []byte{}, challenge: nil, serverErr: true, more: false},
		},
	},
	15: {
		skipClient: true,
		mechanism:  plain,
		perm:       acceptAll,
		steps: []saslStep{
			{resp: []byte("Ursel\x00Kurt\x00xipj3plmq\x00"), serverErr: true, more: false},
		},
	},
	16: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-256-PLUS", sha256.New),
		clientOpts: []Option{
			RemoteMechanisms("SCRAM-SHA-256-PLUS"),
			Credentials(func() ([]byte, []byte, []byte) {
				return []byte("user"), []byte("pencil"), []byte("admin")
			}),
			TLSState(tls.ConnectionState{TLSUnique: []byte{}}),
		},
		steps: []saslStep{
			{
				resp: []byte("p=tls-unique,a=admin,n=user,r=fyko+d2lbbFgONRv9qkxdawL"),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`),
				clientErr: true,
			},
		},
	},
	17: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-256-PLUS", sha256.New),
		clientOpts: []Option{
			RemoteMechanisms("SCRAM-SHA-256-PLUS"),
			Credentials(func() ([]byte, []byte, []byte) {
				return []byte("user"), []byte("pencil"), []byte("admin")
			}),
			TLSState(tls.ConnectionState{TLSUnique: nil}),
		},
		steps: []saslStep{
			{
				resp: []byte("p=tls-unique,a=admin,n=user,r=fyko+d2lbbFgONRv9qkxdawL"),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`),
				clientErr: true,
			},
		},
	},
	18: {
		skipServer: true,
		mechanism:  scram("SCRAM-SHA-256-PLUS", sha256.New),
		clientOpts: []Option{
			Credentials(func() ([]byte, []byte, []byte) {
				return []byte("user"), []byte("pencil"), []byte("admin")
			}),
			RemoteMechanisms("SCRAM-SHA-256-PLUS"),
		},
		steps: []saslStep{
			{
				resp: []byte("n,a=admin,n=user,r=fyko+d2lbbFgONRv9qkxdawL"),
				more: true,
			},
			{
				challenge: []byte(`r=fyko+d2lbbFgONRv9qkxdawL%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`),
				clientErr: true,
			},
		},
	},
}

func testClient(t *testing.T, client *Negotiator, tc saslTest, run int) {
	t.Run("Client", func(t *testing.T) {
		for _, step := range tc.steps {
			more, resp, err := client.Step(step.challenge)
			switch {
			case err != nil && client.State()&Errored != Errored:
				t.Logf("Run %d, Step %s", run, getStepName(client))
				t.Fatalf("State machine internal error state was not set, got error: %v", err)
			case err == nil && client.State()&Errored == Errored:
				t.Logf("Run %d, Step %s", run, getStepName(client))
				t.Fatal("State machine internal error state was set, but no error was returned")
			case err == nil && step.clientErr:
				// There was no error, but we expect one
				t.Logf("Run %d, Step %s", run, getStepName(client))
				t.Fatal("Expected SASL step to error")
			case err != nil && !step.clientErr:
				// There was an error, but we didn't expect one
				t.Logf("Run %d, Step %s", run, getStepName(client))
				t.Fatalf("Got unexpected SASL error: %v", err)
			case string(step.resp) != string(resp):
				t.Logf("Run %d, Step %s", run, getStepName(client))
				t.Fatalf("Got invalid response text:\nexpected `%s'\n     got `%s'", step.resp, resp)
			case more != step.more:
				t.Logf("Run %d, Step %s", run, getStepName(client))
				t.Fatalf("Got unexpected value for more: %v", more)
			}
		}
	})
}

func testServer(t *testing.T, server *Negotiator, tc saslTest, run int) {
	t.Run("Server", func(t *testing.T) {
		for _, step := range tc.steps {
			more, challenge, err := server.Step(step.resp)
			switch {
			case err != nil && server.State()&Errored != Errored:
				t.Logf("Run %d, Step %s", run, getStepName(server))
				t.Fatalf("State machine internal error state was not set, got error: %v", err)
			case err == nil && server.State()&Errored == Errored:
				t.Logf("Run %d, Step %s", run, getStepName(server))
				t.Fatal("State machine internal error state was set, but no error was returned")
			case err == nil && step.serverErr:
				// There was no error, but we expect one
				t.Logf("Run %d, Step %s", run, getStepName(server))
				t.Fatal("Expected SASL step to error")
			case err != nil && !step.serverErr:
				// There was an error, but we didn't expect one
				t.Logf("Run %d, Step %s", run, getStepName(server))
				t.Fatalf("Got unexpected SASL error: %v", err)
			case string(step.challenge) != string(challenge):
				t.Logf("Run %d, Step %s", run, getStepName(server))
				t.Fatalf("Got invalid challenge text:\nexpected `%s'\n     got `%s'", step.challenge, challenge)
			case more != step.more:
				t.Logf("Run %d, Step %s", run, getStepName(server))
				t.Fatalf("Got unexpected value for more: %v", more)
			}
		}
	})
}

func TestSASL(t *testing.T) {
	for i, tc := range saslTestCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			client := NewClient(tc.mechanism, tc.clientOpts...)
			server := NewServer(tc.mechanism, tc.perm, tc.serverOpts...)

			// Run each test twice to make sure that Reset actually sets the state back
			// to the initial state.
			for run := 1; run < 3; run++ {
				// Reset the nonce to the one used by all of our test vectors.
				// TODO: this is an internal state detail. Instead of mutating it, make
				// an option to set the RNG and pass in a dummy one.
				client.nonce = testNonce
				server.nonce = testNonce

				if !tc.skipClient {
					testClient(t, client, tc, run)
				}
				if !tc.skipServer {
					testServer(t, server, tc, run)
				}

				client.Reset()
				server.Reset()
			}
		})
	}
}
