// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on custom regexp (--pattern)

package mirai

import (
	"bytes"
	"errors"
	"github.com/zmap/zgrab2"
	"log"
	"time"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
}

var NoMatchError = errors.New("pattern did not match")

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var m Module
	_, err := zgrab2.AddCommand("mirai", "mirai", m.Description(), 42061, &m)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (s *Scanner) Protocol() string {
	return "mirai"
}

// InitPerSender initializes the scanner for a given sender.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {

	return nil
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "tries to detect mirai botnet"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	return nil
}

func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	var results Results
	conn, err := target.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	_, err = conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return zgrab2.SCAN_CONNECTION_CLOSED, nil, err
	}
	time.Sleep(500 * time.Millisecond) //FIX ME: we can't manually force send the packet and the server side checks for packet length...
	_, err = conn.Write([]byte{0x13, 0x37})
	if err != nil {
		return zgrab2.SCAN_CONNECTION_CLOSED, nil, err
	}

	bannerSlice, err := zgrab2.ReadAvailableWithOptions(conn, 2, 500*time.Millisecond, 0, 2)
	if bannerSlice != nil {
		if bytes.Equal(bannerSlice, []byte{0x13, 0x37}) {
			return zgrab2.SCAN_SUCCESS, &results, nil
		}
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, NoMatchError
}
