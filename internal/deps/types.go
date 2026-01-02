package deps

type PackageRef struct {
	Ecosystem string
	Name      string
	Version   string
	Source    string // file that referenced it
}
