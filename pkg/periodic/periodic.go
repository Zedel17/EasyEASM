package periodic

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/g0ldencybersec/EasyEASM/pkg/active"
	"github.com/g0ldencybersec/EasyEASM/pkg/configparser"
	"github.com/g0ldencybersec/EasyEASM/pkg/passive"
	"github.com/g0ldencybersec/EasyEASM/pkg/utils"
	"github.com/robfig/cron/v3"
)

// go.mod is changed! gocron pkg imported

func PeriodicSet(cfg configparser.Config) {

	if cfg.RunConfig.RunType == "fast" {
		RunPeriodicFast(cfg, cfg.RunConfig.RequestsSeconds)

	} else if cfg.RunConfig.RunType == "complete" {
		RunPeriodicComplete(cfg, cfg.RunConfig.RequestsSeconds)
	}
}

func RunPeriodicFast(cfg configparser.Config, ratelimit int) {
	s := cron.New(cron.WithLogger(cron.VerbosePrintfLogger(log.New(os.Stdout, "cron: ", log.LstdFlags))))
	frequency := fmt.Sprintf("0 0 */" + strconv.Itoa(cfg.RunConfig.PeriodicDays) + " * *")

	//periodic scheduler test every tot days
	s.AddFunc(frequency, func() {
		if _, err := os.Stat("EasyEASM.csv"); err == nil {
			fmt.Println("Found data from previous run!")
			e := os.Rename("EasyEASM.csv", "old_EasyEASM.csv")
			if e != nil {
				panic(e)
			}
		}

		if _, err := os.Stat("EasyEASM.json"); err == nil {
			fmt.Println("Found data from previous Nuclei scan!")
			e := os.Rename("EasyEASM.json", "old_EasyEASM.json")
			if e != nil {
				panic(e)
			}
		}

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

		//start the nuclei func
		flag := []string{"std"}
		Runner.RunNuclei(flag, cfg.RunConfig.ActiveThreads, ratelimit)

		//notify both new domains and vulnerabilities
		if strings.Contains(cfg.RunConfig.SlackWebhook, "https") {
			utils.NotifyVulnSlack(cfg.RunConfig.SlackWebhook)
			utils.NotifyNewDomainsSlack(Runner.Subdomains, cfg.RunConfig.SlackWebhook)

			os.Remove("old_EasyEASM.json")
			os.Remove("old_EasyEASM.csv")
		} else if strings.Contains(cfg.RunConfig.DiscordWebhook, "https") {
			utils.NotifyVulnDiscord(cfg.RunConfig.DiscordWebhook)
			utils.NotifyNewDomainsDiscord(Runner.Subdomains, cfg.RunConfig.DiscordWebhook)

			os.Remove("old_EasyEASM.json")
			os.Remove("old_EasyEASM.csv")
		}

	})

	//start the cron job
	s.Start()
	//wait indefinetly to keep running the func
	select {}
}

func RunPeriodicComplete(cfg configparser.Config, ratelimit int) {
	frequency := fmt.Sprintf("0 0 */" + strconv.Itoa(cfg.RunConfig.PeriodicDays) + " * *")
	s := cron.New(cron.WithLogger(cron.VerbosePrintfLogger(log.New(os.Stdout, "cron: ", log.LstdFlags))))

	//s.AddFunc(frequency, func(){})
	//periodic scheduler test every 5 min
	s.AddFunc(frequency, func() {
		fmt.Printf("\n\n")
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
		fmt.Println("Running Nuclei")
		flag := []string{"std"}
		PassiveRunner.RunNuclei(flag, cfg.RunConfig.ActiveThreads, ratelimit)

		if strings.Contains(cfg.RunConfig.DiscordWebhook, "https") {
			utils.NotifyNewDomainsSlack(ActiveRunner.Subdomains, cfg.RunConfig.SlackWebhook)
			utils.NotifyVulnSlack(cfg.RunConfig.SlackWebhook)
			os.Remove("old_EasyEASM.json")
			os.Remove("old_EasyEASM.csv")
		}
		if strings.Contains(cfg.RunConfig.DiscordWebhook, "https") {
			utils.NotifyNewDomainsDiscord(ActiveRunner.Subdomains, cfg.RunConfig.DiscordWebhook)
			utils.NotifyVulnDiscord(cfg.RunConfig.DiscordWebhook)
			os.Remove("old_EasyEASM.json")
			os.Remove("old_EasyEASM.csv")
		}

	})

	//start the cron job
	s.Start()
	//wait indefinetly to keep running the func
	select {}
}
