package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readPredicate(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var predicate interface{}
	if err := json.Unmarshal(data, &predicate); err != nil {
		return nil, err
	}
	return predicate, nil
}

func uploadToTlog(ctx context.Context, sv *sign.SignerVerifier, rekorURL string, signedPayload []byte) error {
	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return err
	}

	rekorClient, err := rekor.NewClient(rekorURL)
	if err != nil {
		return err
	}
	entry, err := cosign.TLogUploadInTotoAttestation(ctx, rekorClient, signedPayload, rekorBytes)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return nil
}

func attest(predicateType, predicatePath, blobPath string) error {
	digest, err := fileDigest(blobPath)
	if err != nil {
		return err
	}

	predicate, err := readPredicate(predicatePath)
	if err != nil {
		return err
	}

	st := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: predicateType,
			Subject: []in_toto.Subject{
				{
					Name: predicatePath,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
		},
		Predicate: attestation.CosignPredicate{
			Data: predicate,
		},
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ko := options.KeyOpts{
		FulcioURL:    options.DefaultFulcioURL,
		RekorURL:     options.DefaultRekorURL,
		OIDCIssuer:   options.DefaultOIDCIssuerURL,
		OIDCClientID: "sigstore",

		InsecureSkipFulcioVerify: false,
		SkipConfirmation:         true,
	}

	sv, err := sign.SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)

	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	fmt.Println(string(signedPayload))

	err = uploadToTlog(ctx, sv, ko.RekorURL, signedPayload)

	return nil

}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("usage: %s PREDICATE_TYPE PREDICATE_PATH BLOB_PATH\n", os.Args[0])
		os.Exit(1)
	}

	rawPredicateType := os.Args[1]
	var predicateType string
	switch rawPredicateType {
	case "cyclonedx":
		predicateType = in_toto.PredicateCycloneDX
	default:
		fmt.Println("invalid predicate type")
		os.Exit(1)
	}

	predicatePath := os.Args[2]
	blobPath := os.Args[3]
	err := attest(predicateType, predicatePath, blobPath)
	if err != nil {
		panic(err)
	}

}
