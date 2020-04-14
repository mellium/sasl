// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl_test

import (
	"fmt"

	"mellium.im/sasl"
)

func Example_plainSuccess() {
	const (
		username = "miranda"
		password = "pencil"
	)

	creds := sasl.Credentials(func() ([]byte, []byte, []byte) {
		// In a real auth system this would probably be user input.
		return []byte(username), []byte(password), []byte{}
	})

	server := sasl.NewServer(sasl.Plain, func(n *sasl.Negotiator) bool {
		user, pass, ident := n.Credentials()
		// In a real auth system you might want to consider a constant time
		// comparison and this would probably involve hashing and a database lookup.
		if len(ident) == 0 && string(user) == username && string(pass) == password {
			fmt.Println("auth success!")
			return true
		}
		fmt.Println("auth failed!")
		return false
	}, creds)

	client := sasl.NewClient(sasl.Plain, creds)

	_, resp, err := client.Step(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Normally the response would come from the network, not from a client on the
	// same machine.
	_, _, err = server.Step(resp)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Output: auth success!
}

func Example_plainFailure() {
	const (
		username = "miranda"
		password = "pencil"
	)

	creds := sasl.Credentials(func() ([]byte, []byte, []byte) {
		return []byte(username), []byte(password), []byte{}
	})

	server := sasl.NewServer(sasl.Plain, func(n *sasl.Negotiator) bool {
		user, pass, ident := n.Credentials()
		// In a real auth system you might want to consider a constant time
		// comparison and this would probably involve hashing and a database lookup.
		if len(ident) == 0 && string(user) == username && string(pass) == password {
			fmt.Println("auth success!")
			return true
		}
		fmt.Println("auth failed!")
		return false
	}, creds)

	client := sasl.NewClient(sasl.Plain, sasl.Credentials(func() ([]byte, []byte, []byte) {
		// In a real auth system this would probably be user input.
		return []byte(username), []byte("password!"), []byte{}
	}))

	_, resp, err := client.Step(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Normally the response would come from the network, not from a client on the
	// same machine.
	_, _, err = server.Step(resp)
	if err != sasl.ErrAuthn {
		fmt.Println(err)
		return
	}

	// Output: auth failed!
}
