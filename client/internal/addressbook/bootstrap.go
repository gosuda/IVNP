package addressbook

import (
	"maps"
)

var bootstrapHostNames = []string{
	"reg.i2p",
	"identiguy.i2p",
	"stats.i2p",
	"exit.stormycloud.i2p",
	"i2p-projekt.i2p",
	"zzz.i2p",
}

var defaultBootstrapHosts = map[string]string{
	"reg.i2p":              "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p",
	"identiguy.i2p":        "EhDXPsItHi7Dfx8~~0iHPzkjiK1568wqEifARTr-ngIznwVaBmeEnSHXfLkA-7F~Nrqw95yQLlZpja6N1DyQNtJXPx-Db3apXuKwsuTNSGgZme2kFHXPh7PCsfzARwxn4d2-Nx75V4BSCgQr0gRjDa~L~JmtxPRUpZX2NyBvD0w5MSaD~9t4RuCRQ2gVDpUUDcTh2jkm2bX-R9vRIHhCZLasHxDR7rJC9-38uMsQ6ywd4ulQQYIs0kB1sEofdXUypyqphQU9xIxz7azgzKJp~dHnJpJ6SpaH7UrDN-YfOkAvGFBbk9k-u3NGl571Y205dQF~l3XHvVKf6NS9~JvtVh0JibwQ2qLVPy3Y~TtViffvpunNGOrfnVrT5-1c3lWNHx8gTalY3R-vU5rDd8Bz3AhNM6KWktZq8LiHHhJUxIkebXZsid-f2g~QgRRywxG7ksIlKsCMEn076f03L-oWJIlrAg5MdQd-qlg1Bs1IhrR8YT8jNYrX1bGdlmPrJDpiAAAA",
	"stats.i2p":            "Okd5sN9hFWx-sr0HH8EFaxkeIMi6PC5eGTcjM1KB7uQ0ffCUJ2nVKzcsKZFHQc7pLONjOs2LmG5H-2SheVH504EfLZnoB7vxoamhOMENnDABkIRGGoRisc5AcJXQ759LraLRdiGSR0WTHQ0O1TU0hAz7vAv3SOaDp9OwNDr9u902qFzzTKjUTG5vMTayjTkLo2kOwi6NVchDeEj9M7mjj5ySgySbD48QpzBgcqw1R27oIoHQmjgbtbmV2sBL-2Tpyh3lRe1Vip0-K0Sf4D-Zv78MzSh8ibdxNcZACmZiVODpgMj2ejWJHxAEz41RsfBpazPV0d38Mfg4wzaS95R5hHx6eh7oG61KBN1cO1oY8M2oQfISCCpWHPm4WzOlfOHyZOzUHOpcYERAFbsO~w0-ryKIjZJeTzmc314vQB3gG8zMhPRWy9ff6BMkI492DQG2Qv0y3f5fRtx3BfzD7POhujoICzbs8XiCOuuAu8BO0u3k903uHAPNurZx~0jG05TdBQAEAAcAAA==",
	"exit.stormycloud.i2p": "5d4s7pcvfdpftfk7npc7hllyujhufsdprtrf4o53i44rgsa2xbwa.b32.i2p",
	"i2p-projekt.i2p":      "8ZAW~KzGFMUEj0pdchy6GQOOZbuzbqpWtiApEj8LHy2~O~58XKxRrA43cA23a9oDpNZDqWhRWEtehSnX5NoCwJcXWWdO1ksKEUim6cQLP-VpQyuZTIIqwSADwgoe6ikxZG0NGvy5FijgxF4EW9zg39nhUNKRejYNHhOBZKIX38qYyXoB8XCVJybKg89aMMPsCT884F0CLBKbHeYhpYGmhE4YW~aV21c5pebivvxeJPWuTBAOmYxAIgJE3fFU-fucQn9YyGUFa8F3t-0Vco-9qVNSEWfgrdXOdKT6orr3sfssiKo3ybRWdTpxycZ6wB4qHWgTSU5A-gOA3ACTCMZBsASN3W5cz6GRZCspQ0HNu~R~nJ8V06Mmw~iVYOu5lDvipmG6-dJky6XRxCedczxMM1GWFoieQ8Ysfuxq-j8keEtaYmyUQme6TcviCEvQsxyVirr~dTC-F8aZ~y2AlG5IJz5KD02nO6TRkI2fgjHhv9OZ9nskh-I2jxAzFP6Is1kyAAAA",
	"zzz.i2p":              "GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==",
}

// DefaultBootstrapHosts returns a copy of verified seed mappings for core I2P services.
func DefaultBootstrapHosts() map[string]string {
	return maps.Clone(defaultBootstrapHosts)
}
