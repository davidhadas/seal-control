/*
Copyright 2023 David Hadas

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

package certificates

import (
	"bytes"
	"testing"
)

func TestSealDataMap_EncryptItem_DecryptItem(t *testing.T) {
	tests := []struct {
		name           string
		key            []byte
		in             []byte
		wantErrEncrypt bool
	}{
		{name: "empty buf in", key: []byte("1234567812345678"), in: []byte("")},
		{name: "simple", key: []byte("1234567812345678"), in: []byte("test")},
		{name: "char", key: []byte("1234567812345678"), in: []byte("a")},
		{name: "nonchar", key: []byte("1234567812345678"), in: []byte{0}},
		{name: "no key", key: []byte{}, in: []byte{0}, wantErrEncrypt: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd := &SealDataMap{}

			gotSealedtext, err := sd.EncryptItem(tt.key, "x", tt.in)
			if (err != nil) != tt.wantErrEncrypt {
				t.Errorf("EncryptItem() error = %v, wantErr %v", err, tt.wantErrEncrypt)
				return
			}
			if tt.wantErrEncrypt {
				return
			}

			out, err := sd.DecryptItem(tt.key, "x", gotSealedtext)
			if err != nil {
				t.Errorf("DecryptItem() error = %v", err)
				return
			}
			if !bytes.Equal(tt.in, out) {
				t.Errorf("EncryptItem - DecryptItem MISMATCH %s (%d), expected %s (%d)", out, len(out), tt.in, len(tt.in))
				return
			}
		})
	}

	t.Run("Any byte", func(t *testing.T) {
		sd := &SealDataMap{}
		inbase := make([]byte, 256)

		for i := 0; i <= 20; i++ {
			in := append([]byte(nil), inbase[:i]...)

			gotSealedtext, err := sd.EncryptItem([]byte("1234567812345678"), "x", in)
			if err != nil {
				t.Errorf("EncryptItem() error = %v", err)
				return
			}
			out, err := sd.DecryptItem([]byte("1234567812345678"), "x", gotSealedtext)
			if err != nil {
				t.Errorf("DecryptItem() error = %v", err)
				return
			}
			if !bytes.Equal(in, out) {
				t.Errorf("EncryptItem - DecryptItem MISMATCH %v (%d), expected %v (%d)", out, len(out), in, len(in))
			}
		}
	})

}
