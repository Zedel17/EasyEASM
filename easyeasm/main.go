package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/g0ldencybersec/EasyEASM/pkg/active"
	"github.com/g0ldencybersec/EasyEASM/pkg/configparser"
	"github.com/g0ldencybersec/EasyEASM/pkg/flags"
	"github.com/g0ldencybersec/EasyEASM/pkg/passive"
	"github.com/g0ldencybersec/EasyEASM/pkg/periodic"
	"github.com/g0ldencybersec/EasyEASM/pkg/utils"
)

func main() {
	// install required tools
	utils.InstallTools()

	// print a banner
	banner := "\x1b[36m****************\n\nEASY EASM\n\n***************\x1b[0m\n"
	fmt.Println(banner)

	//check if flag '-i' is provided when running the tool, if yes return the interactive parameter
	flag, value := flags.ParsingFlags()

	// parse the configuration file
	cfg := configparser.ParseConfig(flag)

	//check if values for threads and ratelimit are provided as flags
	//standard value for ratelimit is 150 (nuclei standard)

	if len(value) == 2 {
		if value[0] > -1 {
			//set the ratelimit for the request per second with the nuclei tool
			//change the thread config for this run only, not for the config file
			cfg.RunConfig.RequestsSeconds = value[0]
			fmt.Println("Rate Limit setted correctly")
		}
		if value[1] > -1 {
			//change the thread config for this run only, not for the config file
			cfg.RunConfig.ActiveThreads = value[1]
			fmt.Println("Thread value setted correctly")
		}
	} else {
		panic("Invalid parse of flag values")
	}

	// check for previous run file
	var prevRun bool
	if _, err := os.Stat("EasyEASM.csv"); err == nil {
		fmt.Println("Found data from previous run!")
		prevRun = true
		e := os.Rename("EasyEASM.csv", "old_EasyEASM.csv")
		if e != nil {
			panic(e)
		}
	} else {
		fmt.Println("No previous run data found")
		prevRun = false
	}

	// check the run type specified in the config and perform actions accordingly
	if strings.ToLower(cfg.RunConfig.RunType) == "fast" {
		// fast run: passive enumeration only

		// create a PassiveRunner instance
		Runner := passive.PassiveRunner{
			SeedDomains: cfg.RunConfig.Domains,
		}

		// run passive enumeration and get the results
		passiveResults := Runner.RunPassiveEnum()

		// remove duplicate subdomains
		Runner.Subdomains = utils.RemoveDuplicates(passiveResults)
		Runner.Results = len(Runner.Subdomains)

		fmt.Printf("\x1b[31mFound %d subdomains\n\n\x1b[0m", Runner.Results)
		fmt.Println(Runner.Subdomains)
		fmt.Println("Checking which domains are live and generating assets csv...")

		// run Httpx to check live domains
		Runner.RunHttpx()

		// run the nuclei prompt
		PromptOptionsNuclei(Runner, cfg, flag)

		// notify about new domains if prevRun is true
		if prevRun && strings.Contains(cfg.RunConfig.SlackWebhook, "https") {
			utils.NotifyNewDomainsSlack(Runner.Subdomains, cfg.RunConfig.SlackWebhook)
			os.Remove("old_EasyEASM.csv")
		} else if prevRun && strings.Contains(cfg.RunConfig.DiscordWebhook, "https") {
			utils.NotifyNewDomainsDiscord(Runner.Subdomains, cfg.RunConfig.DiscordWebhook)
			os.Remove("old_EasyEASM.csv")
		}

		// check if the periodic flag is provided, if yes start the periodic scan
		if utils.Contains(flag, "periodic") {
			periodic.PeriodicSet(cfg)
		}

	} else if strings.ToLower(cfg.RunConfig.RunType) == "complete" {
		// complete run: passive and active enumeration

		// passive enumeration
		PassiveRunner := passive.PassiveRunner{
			SeedDomains: cfg.RunConfig.Domains,
		}
		passiveResults := PassiveRunner.RunPassiveEnum()

		// remove duplicate subdomains
		PassiveRunner.Subdomains = utils.RemoveDuplicates(passiveResults)
		PassiveRunner.Results = len(PassiveRunner.Subdomains)

		// active enumeration
		ActiveRunner := active.ActiveRunner{
			SeedDomains: cfg.RunConfig.Domains,
		}
		activeResults := ActiveRunner.RunActiveEnum(cfg.RunConfig.ActiveWordlist, cfg.RunConfig.ActiveThreads)
		activeResults = append(activeResults, passiveResults...)

		ActiveRunner.Subdomains = utils.RemoveDuplicates(activeResults)

		// permutation scan
		permutationResults := ActiveRunner.RunPermutationScan(cfg.RunConfig.ActiveThreads)
		ActiveRunner.Subdomains = append(ActiveRunner.Subdomains, permutationResults...)
		ActiveRunner.Subdomains = utils.RemoveDuplicates(ActiveRunner.Subdomains)
		ActiveRunner.Results = len(ActiveRunner.Subdomains)

		// httpx scan
		fmt.Printf("Found %d subdomains\n\n", ActiveRunner.Results)
		fmt.Println(ActiveRunner.Subdomains)
		fmt.Println("Checking which domains are live and generating assets csv...")
		ActiveRunner.RunHttpx()

		//nuclei function start
		PromptOptionsNuclei(PassiveRunner, cfg, flag)

		// notify about new domains if prevRun is true
		if prevRun && strings.Contains(cfg.RunConfig.SlackWebhook, "https") {
			utils.NotifyNewDomainsSlack(ActiveRunner.Subdomains, cfg.RunConfig.SlackWebhook)
			os.Remove("old_EasyEASM.csv")
		} else if prevRun && strings.Contains(cfg.RunConfig.DiscordWebhook, "https") {
			utils.NotifyNewDomainsDiscord(ActiveRunner.Subdomains, cfg.RunConfig.DiscordWebhook)
			os.Remove("old_EasyEASM.csv")
		}

		// check if the periodic flag is provided, if yes start the periodic scan
		if utils.Contains(flag, "periodic") {
			periodic.PeriodicSet(cfg)
		}

	} else {
		// invalid run mode specified
		panic("Please pick a valid run mode and add it to your config.yml file! You can set runType to either 'fast' or 'complete'")
	}
}

// func is here and not in nuclei path to avoid having to modify the current structure of the pkg (import cycle with passive)
// it can probably be adjusted to make the main cleaner
func PromptOptionsNuclei(r passive.PassiveRunner, cfg configparser.Config, flags []string) {

	//check if interactive mod is active (flag -i)
	if utils.Contains(flags, "interactive") {
		//vuln scan starting
		reader := bufio.NewReader(os.Stdin)
		opt, _ := utils.GetInput("Do you want to run the vulnerability scanner? y/n\n", reader)
		switch opt {
		case "y":
			fmt.Println("Running Nuclei")

			var prevRunNuclei bool
			if _, err := os.Stat("EasyEASM.json"); err == nil {
				fmt.Println("Found data from previous Nuclei scan!")
				prevRunNuclei = true
				e := os.Rename("EasyEASM.json", "old_EasyEASM.json")
				if e != nil {
					panic(e)
				}
			} else {
				fmt.Println("No previous Nuclei scan data found")
				prevRunNuclei = false
			}

			// start the nuclei func
			r.RunNuclei(flags, cfg.RunConfig.ActiveThreads, cfg.RunConfig.RequestsSeconds)

			// notify discord and slack if present
			if prevRunNuclei && strings.Contains(cfg.RunConfig.SlackWebhook, "https") {
				utils.NotifyVulnSlack(cfg.RunConfig.SlackWebhook)
				os.Remove("old_EasyEASM.json")
			} else if prevRunNuclei && strings.Contains(cfg.RunConfig.DiscordWebhook, "https") {
				utils.NotifyVulnDiscord(cfg.RunConfig.DiscordWebhook)
				os.Remove("old_EasyEASM.json")
			}

		case "n":
			return

		default:
			// invalid option chosen at runtime
			fmt.Println("Choose a valid option")
			PromptOptionsNuclei(r, cfg, flags)
		}
	} else {
		// std run without any console prompt
		fmt.Println("Running Nuclei")

		var prevRunNuclei bool
		if _, err := os.Stat("EasyEASM.json"); err == nil {
			fmt.Println("Found data from previous Nuclei scan!")
			prevRunNuclei = true
			e := os.Rename("EasyEASM.json", "old_EasyEASM.json")
			if e != nil {
				panic(e)
			}
		} else {
			fmt.Println("No previous Nuclei scan data found")
			prevRunNuclei = false
		}

		// run the nuclei func
		r.RunNuclei(flags, cfg.RunConfig.ActiveThreads, cfg.RunConfig.RequestsSeconds)

		// notify discord and slack if presents
		if prevRunNuclei && strings.Contains(cfg.RunConfig.SlackWebhook, "https") {
			utils.NotifyVulnSlack(cfg.RunConfig.SlackWebhook)
			os.Remove("old_EasyEASM.json")
		} else if prevRunNuclei && strings.Contains(cfg.RunConfig.DiscordWebhook, "https") {
			utils.NotifyVulnDiscord(cfg.RunConfig.DiscordWebhook)
			os.Remove("old_EasyEASM.json")
		}
		return
	}
}
