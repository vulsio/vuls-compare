# vuls-compare
## When comparing the detection logic of vuls0 and vuls2
### Example

```console
$ cd detection

$ ls
config.toml  go.mod  gost.sqlite3  main.go  vuls*  go.sum  oval.sqlite3  vuls.db

$ ./vuls -v
vuls-0.28.0-703ba6616050cba7c67365a12e7d98eb06f459ba-2024-12-08T08:37:23Z

$ cat config.toml
[cveDict]
type = "sqlite3"

[ovalDict]
type = "sqlite3"
sqlite3Path = "/home/vuls/vuls-compare/detection/oval.sqlite3"

[gost]
type = "sqlite3"
sqlite3Path = "/home/vuls/vuls-compare/detection/gost.sqlite3"

[exploit]
type = "sqlite3"

[metasploit]
type = "sqlite3"

[kevuln]
type = "sqlite3"

[cti]
type = "sqlite3"

$ go run main.go ../testdata/9/2024-12-07T09-49-40+0900/vagrant.json vuls config.toml vuls.db
```

## When comparing the DB difference of vuls2 using vuls0
### Example
```console
$ cd db

$ ls
go.mod  go.sum  main.go  vuls.after.db  vuls.before.db

$ go run main.go ../testdata/9/2024-12-07T09-49-40+0900/vagrant.json vuls.before.db vuls.after.db
```