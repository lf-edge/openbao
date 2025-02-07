// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImportMultiple(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Create a root CA.
	resp, err := CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name": "root example.com",
		"issuer_name": "root",
		"key_type":    "ec",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data["certificate"])
	oldRoot := resp.Data["certificate"].(string)

	// Create a role for issuance.
	_, err = CBWrite(b, s, "roles/local-testing", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
		"ttl":               "75s",
		"no_store":          "true",
	})
	require.NoError(t, err)

	resp, err = CBWrite(b, s, "issuers/import/bundle", map[string]interface{}{
		"pem_bundle": oldRoot,
	})
	require.NoError(t, err)

	// Print the response data.
	fmt.Printf("response Data: %+v\n", resp.Data)

	// Sample PEM bundle with a certificate and private key.
	testBundle := `
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhyb290
LW5ldzAeFw0yMjA4MjQxMjEzNTVaFw0yMzA5MDMxMjEzNTVaMBMxETAPBgNVBAMM
CHJvb3QtbmV3MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojTA/Mx7
LVW/Zgn/N4BqZbaF82MrTIBFug3ob7mqycNRlWp4/PH8v37+jYn8e691HUsKjden
rDTrO06kiQKiJinAzmlLJvgcazE3aXoh7wSzVG9lFHYvljEmVj+yDbkeaqaCktup
skuNjxCoN9BLmKzZIwVCHn92ZHlhN6LI7CNaU3SDJdu7VftWF9Ugzt9FIvI+6Gcn
/WNE9FWvZ9o7035rZ+1vvTn7/tgxrj2k3XvD51Kq4tsSbqjnSf3QieXT6E6uvtUE
TbPp3xjBElgBCKmeogR1l28rs1aujqqwzZ0B/zOeF8ptaH0aZOIBsVDJR8yTwHzq
s34hNdNfKLHzOwIDAQABo3gwdjAdBgNVHQ4EFgQUF4djNmx+1+uJINhZ82pN+7jz
H8EwHwYDVR0jBBgwFoAUF4djNmx+1+uJINhZ82pN+7jzH8EwDwYDVR0TAQH/BAUw
AwEB/zAOBgNVHQ8BAf8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBAICQovBz4KLWlLmXeZ2Vf6WfQYyGNgGyJa10XNXtWQ5dM2NU
OLAit4x1c2dz+aFocc8ZsX/ikYi/bruT2rsGWqMAGC4at3U4GuaYGO5a6XzMKIDC
nxIlbiO+Pn6Xum7fAqUri7+ZNf/Cygmc5sByi3MAAIkszeObUDZFTJL7gEOuXIMT
rKIXCINq/U+qc7m9AQ8vKhF1Ddj+dLGLzNQ5j3cKfilPs/wRaYqbMQvnmarX+5Cs
k1UL6kWSQsiP3+UWaBlcWkmD6oZ3fIG7c0aMxf7RISq1eTAM9XjH3vMxWQJlS5q3
2weJ2LYoPe/DwX5CijR0IezapBCrin1BscJMLFQ=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCiNMD8zHstVb9m
Cf83gGpltoXzYytMgEW6DehvuarJw1GVanj88fy/fv6Nifx7r3UdSwqN16esNOs7
TqSJAqImKcDOaUsm+BxrMTdpeiHvBLNUb2UUdi+WMSZWP7INuR5qpoKS26myS42P
EKg30EuYrNkjBUIef3ZkeWE3osjsI1pTdIMl27tV+1YX1SDO30Ui8j7oZyf9Y0T0
Va9n2jvTfmtn7W+9Ofv+2DGuPaTde8PnUqri2xJuqOdJ/dCJ5dPoTq6+1QRNs+nf
GMESWAEIqZ6iBHWXbyuzVq6OqrDNnQH/M54Xym1ofRpk4gGxUMlHzJPAfOqzfiE1
018osfM7AgMBAAECggEAAVd6kZZaN69IZITIc1vHRYa2rlZpKS2JP7c8Vd3Z/4Fz
ZZvnJ7LgVAmUYg5WPZ2sOqBNLfKVN/oke5Q0dALgdxYl7dWQIhPjHeRFbZFtjqEV
OXZGBniamMO/HSKGWGrqFf7BM/H7AhClUwQgjnzVSz+B+LJJidM+SVys3n1xuDmC
EP+iOda+bAHqHv/7oCELQKhLmCvPc9v2fDy+180ttdo8EHuxwVnKiyR/ryKFhSyx
K1wgAPQ9jO+V+GESL90rqpX/r501REsIOOpm4orueelHTD4+dnHxvUPqJ++9aYGX
79qBNPPUhxrQI1yoHxwW0cTxW5EqkZ9bT2lSd5rjcQKBgQDNyPBpidkHPrYemQDT
RldtS6FiW/jc1It/CRbjU4A6Gi7s3Cda43pEUObKNLeXMyLQaMf4GbDPDX+eh7B8
RkUq0Q/N0H4bn1hbxYSUdgv0j/6czpMo6rLcJHGwOTSpHGsNsxSLL7xlpgzuzqrG
FzEgjMA1aD3w8B9+/77AoSLoMQKBgQDJyYMw82+euLYRbR5Wc/SbrWfh2n1Mr2BG
pp1ZNYorXE5CL4ScdLcgH1q/b8r5XGwmhMcpeA+geAAaKmk1CGG+gPLoq20c9Q1Y
Ykq9tUVJasIkelvbb/SPxyjkJdBwylzcPP14IJBsqQM0be+yVqLJJVHSaoKhXZcl
IW2xgCpjKwKBgFpeX5U5P+F6nKebMU2WmlYY3GpBUWxIummzKCX0SV86mFjT5UR4
mPzfOjqaI/V2M1eqbAZ74bVLjDumAs7QXReMb5BGetrOgxLqDmrT3DQt9/YMkXtq
ddlO984XkRSisjB18BOfhvBsl0lX4I7VKHHO3amWeX0RNgOjc7VMDfRBAoGAWAQH
r1BfvZHACLXZ58fISCdJCqCsysgsbGS8eW77B5LJp+DmLQBT6DUE9j+i/0Wq/ton
rRTrbAkrsj4RicpQKDJCwe4UN+9DlOu6wijRQgbJC/Q7IOoieJxcX7eGxcve2UnZ
HY7GsD7AYRwa02UquCYJHIjM1enmxZFhMW1AD+UCgYEAm4jdNz5e4QjA4AkNF+cB
ZenrAZ0q3NbTyiSsJEAtRe/c5fNFpmXo3mqgCannarREQYYDF0+jpSoTUY8XAc4q
wL7EZNzwxITLqBnnHQbdLdAvYxB43kvWTy+JRK8qY9LAMCCFeDoYwXkWV4Wkx/b0
TgM7RZnmEjNdeaa4M52o7VY=
-----END PRIVATE KEY-----
	`

	// Write the PEM bundle to the import endpoint.
	resp, err = CBWrite(b, s, "issuers/import/bundle", map[string]interface{}{
		"pem_bundle":  testBundle,
		"issuer_name": "TestIssuerFriendlyName",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Print the response data.
	fmt.Printf("response Data: %+v\n", resp.Data)

	resp, err = CBList(b, s, "issuers")
	require.NoError(t, err)
	require.Equal(t, 2, len(resp.Data))

	// Print the response data.
	fmt.Printf("\n list: %+v\n", resp.Data)
}
