package file

import (
	"context"

	"github.com/openbao/openbao/api/v2"
)

func cloneClient(ctx context.Context, client *api.Client, pname string) (*api.Client, error) {
	_, err := client.Logical().WriteWithContext(ctx, "sys/namespaces/"+pname, nil)
	if err != nil {
		return nil, err
	}
	clone, err := client.Clone()
	if err != nil {
		return nil, err
	}
	clone.SetToken(client.Token())
	clone.SetNamespace(pname)
	return clone, nil
}
