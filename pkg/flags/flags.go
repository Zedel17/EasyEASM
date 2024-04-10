package flags

import (
	"flag"
	"fmt"
	"os"
)

func ParsingFlags() ([]string, []int) {
	interactive := flag.Bool("i", false, "interactive mode selected")
	periodic := flag.Bool("p", false, "periodic scan")
	help := flag.Bool("h", false, "help mode")

	//parse the maximum value of request per seconds for the nuclei tool if provided, minimum value 1
	var ratelimit int
	//parse the number of threads if provided, minimum value 1
	var threads int
	flag.IntVar(&ratelimit, "rl", -1, "Max requests per second")
	flag.IntVar(&threads, "t", -1, "Max number of threads")

	flag.Parse()

	var flags []string
	var values []int

	if *help {
		file, err := os.Open("help.txt")
		if err != nil {
			//error if opening fails
			panic(err)
		}
		defer file.Close()

		// Read and print the content of the file
		buf := make([]byte, 1024) // Buffer to read the file
		for {
			n, err := file.Read(buf)
			if err != nil && err.Error() != "EOF" {
				//error if reading fails
				panic(err)
			}
			if n == 0 {
				// Exit the loop if end of file is reached
				break
			}
			// Print the read content
			fmt.Print(string(buf[:n]))
		}
		panic("Terminating programme")
	}

	if (ratelimit != -1 && ratelimit < 0) || (threads != -1 && threads < 0) {
		panic("Invalid value for the flag, need to be > 0")
	}
	//append value for rl flag, INDEX FOR RL IS ALWAYS 0
	values = append(values, ratelimit)
	//append value for t flag , INDEX FOR T IS ALWAYS 1
	values = append(values, threads)

	if *interactive && *periodic {
		fmt.Println("Cannot run both interactive mode and periodic")
		panic("Remove one of the two flag")
	}

	//start the interactive mode with runtime config
	if *interactive {
		fmt.Println("Interactive Mode selected")
		flags = append(flags, "interactive")

		return flags, values

	} else if *periodic {
		//start the periodic mode with the provided scheduled time
		fmt.Println("Periodic Mode selected")
		flags = append(flags, "periodic")

		return flags, values

	} else {
		//std run read from config file and does not prompt anything to console at runtime
		flags = append(flags, "std")
		return flags, values

	}
}
