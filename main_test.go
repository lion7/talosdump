package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/siderolabs/talos/pkg/machinery/api/machine"
)

func Test_compileTcpdumpFilterToBpfFilter(t *testing.T) {
	type args struct {
		filter string
	}
	tests := []struct {
		name    string
		args    args
		want    []*machine.BPFInstruction
		wantErr bool
	}{
		{
			"filter pcap traffic",
			args{"not port 50000"},
			[]*machine.BPFInstruction{
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
				{Op: 0x15, Jt: 0, Jf: 8, K: 0x000086dd},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000084},
				{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
				{Op: 0x15, Jt: 0, Jf: 17, K: 0x00000011},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000036},
				{Op: 0x15, Jt: 14, Jf: 0, K: 0x0000c350},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000038},
				{Op: 0x15, Jt: 12, Jf: 13, K: 0x0000c350},
				{Op: 0x15, Jt: 0, Jf: 12, K: 0x00000800},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
				{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000084},
				{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
				{Op: 0x15, Jt: 0, Jf: 8, K: 0x00000011},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x45, Jt: 6, Jf: 0, K: 0x00001fff},
				{Op: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e},
				{Op: 0x48, Jt: 0, Jf: 0, K: 0x0000000e},
				{Op: 0x15, Jt: 2, Jf: 0, K: 0x0000c350},
				{Op: 0x48, Jt: 0, Jf: 0, K: 0x00000010},
				{Op: 0x15, Jt: 0, Jf: 1, K: 0x0000c350},
				{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
				{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
			},
			false,
		},
		{
			"invalid filter",
			args{"not port bogus"},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileTcpdumpFilterToBpfFilter(tt.args.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileTcpdumpFilterToBpfFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("compileTcpdumpFilterToBpfFilter() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func marshalInstructionsToTcpdumpOutput(instructions []*machine.BPFInstruction) string {
	builder := strings.Builder{}
	for _, ins := range instructions {
		builder.WriteString(fmt.Sprintf("{ 0x%x, %d, %d, 0x%08x },\n", ins.Op, ins.Jt, ins.Jf, ins.K))
	}
	return builder.String()
}
