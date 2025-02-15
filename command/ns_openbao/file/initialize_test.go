package file

import (
	"context"
	"os"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

func TestInitialize(t *testing.T) {
	if err := os.RemoveAll(os.TempDir() + "/xdata"); err != nil {
		t.Fatal(err)
	}

	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	sys := client.Sys()
	initResp, err := sys.InitWithContext(ctx, &api.InitRequest{
		SecretShares:    1,
		SecretThreshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	unsealKey := initResp.KeysB64[0]
	keyf, err := os.Create(os.TempDir() + "/unseal.key")
	if err != nil {
		t.Fatal(err)
	}
	defer keyf.Close()
	_, err = keyf.WriteString(unsealKey)
	if err != nil {
		t.Fatal(err)
	}

	token := initResp.RootToken
	tokenf, err := os.Create(os.TempDir() + "/root.token")
	if err != nil {
		t.Fatal(err)
	}
	defer tokenf.Close()
	_, err = tokenf.WriteString(token)
	if err != nil {
		t.Fatal(err)
	}

	tokenf, err = os.Create(os.TempDir() + "/vault.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer tokenf.Close()
	_, err = tokenf.WriteString("export VAULT_TOKEN=" + token)
	if err != nil {
		t.Fatal(err)
	}

	unsealResp, err := sys.UnsealWithOptionsWithContext(ctx, &api.UnsealOpts{
		Key: unsealKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if unsealResp.Sealed ||
		unsealResp.Type != "shamir" ||
		unsealResp.Progress != 0 ||
		unsealResp.StorageType != "file" {
		t.Errorf("Unseal response: %+v", unsealResp)
	}
}

func getClient() (*api.Client, context.Context, error) {
	bs, err := os.ReadFile(os.TempDir() + "/root.token")
	if err != nil {
		return nil, nil, err
	}
	token := string(bs)

	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err == nil {
		client.SetToken(token)
	}
	return client, context.Background(), err
}

func grep(list []string, single string) bool {
	if list == nil {
		return false
	}
	for _, item := range list {
		if item == single {
			return true
		}
	}
	return false
}

func grepi(list []interface{}, single string) bool {
	if list == nil {
		return false
	}
	for _, item := range list {
		if item.(string) == single {
			return true
		}
	}
	return false
}

func TestNamespace(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	logical := client.Logical()

	rootNS := ""
	for _, ns := range []string{"pname", "cname", "dname", "ename"} {
		client.SetNamespace(rootNS)
		_, err = logical.WriteWithContext(ctx, "sys/namespaces/"+ns, nil)
		if err != nil {
			t.Fatal(err)
		}
		rspn, err := logical.ListWithContext(ctx, "sys/namespaces")
		if err != nil {
			t.Fatal(err)
		}
		if rspn.Data == nil ||
			rspn.Data["keys"] == nil ||
			!grepi(rspn.Data["keys"].([]interface{}), ns) {
			t.Errorf("Namespace list: %+v", rspn.Data)
		}
		rootNS += "/" + ns
	}
	for _, ns := range []string{"ename", "dname", "cname", "pname"} {
		rootNS = rootNS[:len(rootNS)-len(ns)-1]
		client.SetNamespace(rootNS)
		_, err = logical.DeleteWithContext(ctx, "sys/namespaces/"+ns)
		if err != nil {
			t.Fatal(err)
		}
		rspn, err := logical.ListWithContext(ctx, "sys/namespaces")
		if err != nil {
			t.Fatal(err)
		}
		if rootNS != "" && rspn != nil { // nil is correct response for zero sub-namespaces?
			t.Errorf("Namespace list: %s => %+v", rootNS, rspn)
		}
	}
}
