package asset

import "testing"

func TestParseAssetIDList(t *testing.T) {
	ids, ok := parseAssetIDList(" 3,1, 3 ,2")
	if !ok || len(ids) != 3 || ids[0] != 3 || ids[1] != 1 || ids[2] != 2 {
		t.Fatalf("got %v %v", ids, ok)
	}
	for _, bad := range []string{"", "0", "1,x", "-1", "1,,2"} {
		if _, ok := parseAssetIDList(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	long := "1"
	for i := 2; i <= maxNetworkLookup+1; i++ {
		long += ",1"
	}
	if _, ok := parseAssetIDList(long); ok {
		t.Fatal("more than one page of ids accepted")
	}
}
