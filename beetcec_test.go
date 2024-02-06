package beetcec_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ethersphere/bee/pkg/crypto"
	"github.com/ethersphere/bee/pkg/pss"
	crypto2 "github.com/ethersphere/bee2/pkg/crypto"
	pss2 "github.com/ethersphere/bee2/pkg/pss"
)

// Validate crypto.EncodeSecp256k1PrivateKey and crypto.DecodeSecp256k1PrivateKey with v1 generated key.
func TestBTCECv1_encoding(t *testing.T) {
	// generate v1 key
	k, err := crypto.GenerateSecp256k1Key()
	assertError(t, err, nil)

	testBTCEC_encoding(t, k)
}

// Validate crypto.EncodeSecp256k1PrivateKey and crypto.DecodeSecp256k1PrivateKey with v2 generated key.
func TestBTCECv2_encoding(t *testing.T) {
	// generate v2 key
	k, err := crypto2.GenerateSecp256k1Key()
	assertError(t, err, nil)

	testBTCEC_encoding(t, k)
}

func testBTCEC_encoding(t *testing.T, k1 *ecdsa.PrivateKey) {
	t.Helper()

	addr, err := crypto2.NewEthereumAddress(k1.PublicKey)
	assertError(t, err, nil)

	t.Run("encode v1 decode v1", func(t *testing.T) {
		d, err := crypto.EncodeSecp256k1PrivateKey(k1)
		assertError(t, err, nil)

		k2, err := crypto.DecodeSecp256k1PrivateKey(d)
		assertError(t, err, nil)

		assertPrivateKeys(t, k1, k2)

		addr2, err := crypto2.NewEthereumAddress(k2.PublicKey)
		assertError(t, err, nil)

		assertBytes(t, addr2, addr)
	})

	t.Run("encode v2 decode v2", func(t *testing.T) {
		d, err := crypto2.EncodeSecp256k1PrivateKey(k1)
		assertError(t, err, nil)

		k2, err := crypto2.DecodeSecp256k1PrivateKey(d)
		assertError(t, err, nil)

		assertPrivateKeys(t, k1, k2)

		addr2, err := crypto2.NewEthereumAddress(k2.PublicKey)
		assertError(t, err, nil)

		assertBytes(t, addr2, addr)
	})

	t.Run("encode v1 decode v2", func(t *testing.T) {
		d, err := crypto.EncodeSecp256k1PrivateKey(k1)
		assertError(t, err, nil)

		k2, err := crypto2.DecodeSecp256k1PrivateKey(d)
		assertError(t, err, nil)

		assertPrivateKeys(t, k1, k2)

		addr2, err := crypto2.NewEthereumAddress(k2.PublicKey)
		assertError(t, err, nil)

		assertBytes(t, addr2, addr)
	})

	t.Run("encode v2 decode v1", func(t *testing.T) {
		d, err := crypto2.EncodeSecp256k1PrivateKey(k1)
		assertError(t, err, nil)

		k2, err := crypto.DecodeSecp256k1PrivateKey(d)
		assertError(t, err, nil)

		if !bytes.Equal(k1.D.Bytes(), k2.D.Bytes()) {
			t.Fatal("encoded and decoded keys are not equal")
		}

		assertPrivateKeys(t, k1, k2)

		addr2, err := crypto2.NewEthereumAddress(k2.PublicKey)
		assertError(t, err, nil)

		assertBytes(t, addr2, addr)
	})
}

// Validate crypto.Signer.Sign and crypto.Recover with v1 generated key.
func TestBTCECv1_recovery(t *testing.T) {
	// generate v1 key
	k, err := crypto.GenerateSecp256k1Key()
	assertError(t, err, nil)

	testBTCEC_recovery(t, k)
}

// Validate crypto.Signer.Sign and crypto.Recover with v2 generated key.
func TestBTCECv2_recovery(t *testing.T) {
	// generate v2 key
	k, err := crypto2.GenerateSecp256k1Key()
	assertError(t, err, nil)

	testBTCEC_recovery(t, k)
}

func testBTCEC_recovery(t *testing.T, k1 *ecdsa.PrivateKey) {
	t.Helper()

	message := []byte("gimme some bytes")

	t.Run("sign v1 recover v1", func(t *testing.T) {
		signer := crypto.NewDefaultSigner(k1)
		signature, err := signer.Sign(message)
		assertError(t, err, nil)

		pubKey, err := crypto.Recover(signature, message)
		assertError(t, err, nil)

		assertPublicKeys(t, pubKey, &k1.PublicKey)
	})

	t.Run("sign v2 recover v2", func(t *testing.T) {
		signer := crypto2.NewDefaultSigner(k1)
		signature, err := signer.Sign(message)
		assertError(t, err, nil)

		pubKey, err := crypto2.Recover(signature, message)
		assertError(t, err, nil)

		assertPublicKeys(t, pubKey, &k1.PublicKey)
	})

	t.Run("sign v1 recover v2", func(t *testing.T) {
		signer := crypto.NewDefaultSigner(k1)
		signature, err := signer.Sign(message)
		assertError(t, err, nil)

		pubKey, err := crypto2.Recover(signature, message)
		assertError(t, err, nil)

		assertPublicKeys(t, pubKey, &k1.PublicKey)
	})

	t.Run("sign v2 recover v1", func(t *testing.T) {
		signer := crypto2.NewDefaultSigner(k1)
		signature, err := signer.Sign(message)
		assertError(t, err, nil)

		pubKey, err := crypto.Recover(signature, message)
		assertError(t, err, nil)

		assertPublicKeys(t, pubKey, &k1.PublicKey)
	})
}

// Validate pss.Wrap and pss.Unwrap with v1 generated key.
func TestBTCECv1_pssTrojanUnwrap(t *testing.T) {
	// generate v1 key
	k, err := crypto.GenerateSecp256k1Key()
	assertError(t, err, nil)

	testBTCEC_pssTrojanUnwrap(t, k)
}

// Validate pss.Wrap and pss.Unwrap with v2 generated key.
func TestBTCECv2_pssTrojanUnwrap(t *testing.T) {
	// generate v2 key
	k, err := crypto2.GenerateSecp256k1Key()
	assertError(t, err, nil)

	testBTCEC_pssTrojanUnwrap(t, k)
}

func testBTCEC_pssTrojanUnwrap(t *testing.T, k1 *ecdsa.PrivateKey) {
	t.Helper()

	t.Run("wrap v1 unwrap v1", func(t *testing.T) {
		topic := pss.NewTopic("topic")
		msg := []byte("some payload")
		pubkey := &k1.PublicKey
		depth := 1
		targets := newTargets(4, depth)

		topic1 := pss.NewTopic("topic-1")
		topic2 := pss.NewTopic("topic-2")

		chunk, err := pss.Wrap(context.Background(), topic, msg, pubkey, targets)
		assertError(t, err, nil)

		unwrapTopic, unwrapMsg, err := pss.Unwrap(context.Background(), k1, chunk, []pss.Topic{topic1, topic2, topic})
		if err != nil {
			t.Fatal(err)
		}

		assertBytes(t, msg, unwrapMsg)
		assertBytes(t, topic[:], unwrapTopic[:])
	})

	t.Run("wrap v2 unwrap v2", func(t *testing.T) {
		topic := pss2.NewTopic("topic")
		msg := []byte("some payload")
		pubkey := &k1.PublicKey
		depth := 1
		targets := newTargets2(4, depth)

		topic1 := pss2.NewTopic("topic-1")
		topic2 := pss2.NewTopic("topic-2")

		chunk, err := pss2.Wrap(context.Background(), topic, msg, pubkey, targets)
		assertError(t, err, nil)

		unwrapTopic, unwrapMsg, err := pss2.Unwrap(context.Background(), k1, chunk, []pss2.Topic{topic1, topic2, topic})
		if err != nil {
			t.Fatal(err)
		}

		assertBytes(t, msg, unwrapMsg)
		assertBytes(t, topic[:], unwrapTopic[:])
	})

	t.Run("wrap v1 unwrap v2", func(t *testing.T) {
		topic := pss.NewTopic("topic")
		msg := []byte("some payload")
		pubkey := &k1.PublicKey
		depth := 1
		targets := newTargets(4, depth)

		topic1 := pss2.NewTopic("topic-1")
		topic2 := pss2.NewTopic("topic-2")

		chunk, err := pss.Wrap(context.Background(), topic, msg, pubkey, targets)
		assertError(t, err, nil)

		unwrapTopic, unwrapMsg, err := pss2.Unwrap(context.Background(), k1, chunk, []pss2.Topic{topic1, topic2, pss2.NewTopic("topic")})
		if err != nil {
			t.Fatal(err)
		}

		assertBytes(t, msg, unwrapMsg)
		assertBytes(t, topic[:], unwrapTopic[:])
	})

	t.Run("wrap v2 unwrap v1", func(t *testing.T) {
		topic := pss2.NewTopic("topic")
		msg := []byte("some payload")
		pubkey := &k1.PublicKey
		depth := 1
		targets := newTargets2(4, depth)

		topic1 := pss.NewTopic("topic-1")
		topic2 := pss.NewTopic("topic-2")

		chunk, err := pss2.Wrap(context.Background(), topic, msg, pubkey, targets)
		assertError(t, err, nil)

		unwrapTopic, unwrapMsg, err := pss.Unwrap(context.Background(), k1, chunk, []pss.Topic{topic1, topic2, pss.NewTopic("topic")})
		if err != nil {
			t.Fatal(err)
		}

		assertBytes(t, msg, unwrapMsg)
		assertBytes(t, topic[:], unwrapTopic[:])
	})
}

func newTargets(length, depth int) pss.Targets {
	targets := make([]pss.Target, length)
	for i := 0; i < length; i++ {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(i))
		targets[i] = pss.Target(buf[:depth])
	}
	return pss.Targets(targets)
}

func newTargets2(length, depth int) pss2.Targets {
	targets := make([]pss2.Target, length)
	for i := 0; i < length; i++ {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(i))
		targets[i] = pss2.Target(buf[:depth])
	}
	return pss2.Targets(targets)
}

func assertError(t testing.TB, got, want error) {
	t.Helper()

	if !errors.Is(got, want) {
		t.Fatalf("got error %[1]T %[1]q, want %[2]T %[2]q", got, want)
	}
}

func assertPrivateKeys(t testing.TB, got, want *ecdsa.PrivateKey) {
	t.Helper()

	if !bytes.Equal(got.D.Bytes(), want.D.Bytes()) {
		t.Errorf("got key D %v, want key D %v", got.D.Bytes(), want.D.Bytes())
	}
}

func assertPublicKeys(t testing.TB, got, want *ecdsa.PublicKey) {
	t.Helper()

	if got.X.Cmp(want.X) != 0 || got.Y.Cmp(want.Y) != 0 {
		t.Fatalf("got %v but want %v", got, &want)
	}
}

func assertBytes(t testing.TB, got, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Errorf("got key D %x, want key D %x", got, want)
	}
}
