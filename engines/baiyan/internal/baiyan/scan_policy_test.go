package baiyan

import (
	"reflect"
	"testing"
)

func TestScanPlanForHost(t *testing.T) {
	// default-web is the explicit --fast policy; the production default is the
	// legacy full-port profile. Pin FastScan so this test matches its assertions.
	app := &App{opts: Options{FastScan: true}}

	tests := []struct {
		host        string
		wantProfile string
		wantPorts   []int
	}{
		{host: "mail.example.com", wantProfile: "mail-light", wantPorts: lowValueSubdomainPorts},
		{host: "smtp-api.example.com", wantProfile: "mail-light", wantPorts: lowValueSubdomainPorts},
		{host: "www.example.com", wantProfile: "default-web", wantPorts: defaultWebPorts},
		{host: "oa.example.com", wantProfile: "default-web", wantPorts: defaultWebPorts},
	}

	for _, tt := range tests {
		gotProfile, gotPorts := app.scanPlanForHost(tt.host)
		if gotProfile != tt.wantProfile {
			t.Fatalf("%s profile = %s, want %s", tt.host, gotProfile, tt.wantProfile)
		}
		if !reflect.DeepEqual(gotPorts, tt.wantPorts) {
			t.Fatalf("%s ports = %v, want %v", tt.host, gotPorts, tt.wantPorts)
		}
	}
}

func TestJoinPorts(t *testing.T) {
	got := joinPorts([]int{8080, 80, 443, 80})
	want := "80,443,8080"
	if got != want {
		t.Fatalf("joinPorts() = %s, want %s", got, want)
	}
}
