# Тестовое задание на стажировку AppSecCloudCamp
1. Задачи в направлении безопасности разработки:разведка во внешней сети, атака первичного доступа, закрепление доступа, повышение привилегий, выход за рамки ДМЗ, проброс трафика в другие сегменты, разведка в локальной сети, захват управления инфраструктурой, противодействие обнаружению и реагированию.
2. Security code review с помощью инструментов статического анализа кода.
3. Поиск уязвимостей с помощью сканеров Nmap, Masscan, Amass, Zenmap.
4. Хочу участвовать в стажировке для приобретения навыков.
### Security code review: GO
```
#поиск уязвимостей кода Go
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var err error

func initDB() {
    db, err = sql.Open("mysql", "user:password@/dbname")
    if err != nil {
        log.Fatal(err)
    }

err = db.Ping()
if err != nil {
    log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

searchQuery := r.URL.Query().Get("query")
if searchQuery == "" {
    http.Error(w, "Query parameter is missing", http.StatusBadRequest)
    return
}

query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
rows, err := db.Query(query)
if err != nil {
    http.Error(w, "Query failed", http.StatusInternalServerError)
    log.Println(err)
    return
}
defer rows.Close()

var products []string
for rows.Next() {
    var name string
    err := rows.Scan(&name)
    if err != nil {
        log.Fatal(err)
    }
    products = append(products, name)
}

fmt.Fprintf(w, "Found products: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

http.HandleFunc("/search", searchHandler)
fmt.Println("Server is running")
log.Fatal(http.ListenAndServe(":8080", nil))
}

#проверка уязвимостей кода спомощью Gosec
sergei@DESKTOP-BBCO7PU:~$ gosec ./...
[gosec] 2024/03/24 09:09:03 Including rules: default
[gosec] 2024/03/24 09:09:04 Excluding rules: default
[gosec] 2024/03/24 09:09:37 Import directory: /home/sergei
[gosec] 2024/03/24 09:10:06 Checking package: main
[gosec] 2024/03/24 09:10:06 Checking file: /home/sergei/zadanie.go.go
Results:

Golang errors in file: [/home/sergei/zadanie.go.go]:

  > [line 8 : column 5] - could not import github.com/go-sql-driver/mysql (invalid package name: "")



[/home/sergei/zadanie.go.go:66] - G114 (CWE-676): Use of net/http serve function that has no support for setting timeouts (Confidence: HIGH, Severity: MEDIUM)
    65: fmt.Println("Server is running")
  > 66: log.Fatal(http.ListenAndServe(":8080", nil))
    67: }



[/home/sergei/zadanie.go.go:38] - G201 (CWE-89): SQL string formatting (Confidence: HIGH, Severity: MEDIUM)
    37:
  > 38: query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
    39: rows, err := db.Query(query)



Summary:
  Gosec  : v2.19.0
  Files  : 1
  Lines  : 67
  Nosec  : 0
  Issues : 2
```
### Security code review: Python
```
#поиск уязвимосей Python
from flask import Flask, request
from jinja2 import Template

app = Flask(name)

@app.route("/page")
def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
return output

if name == "main":
    app.run(debug=True)

#поиск уязвимостей с помощью Pylint
sergei@DESKTOP-BBCO7PU:~$ pylint zadanie2.py
************* Module zadanie2
zadanie2.py:17:0: C0305: Trailing newlines (trailing-newlines)
zadanie2.py:1:0: C0114: Missing module docstring (missing-module-docstring)
zadanie2.py:4:12: E0602: Undefined variable 'name' (undefined-variable)
zadanie2.py:7:0: C0116: Missing function or method docstring (missing-function-docstring)
zadanie2.py:10:4: W0612: Unused variable 'output' (unused-variable)
zadanie2.py:11:0: E0104: Return outside function (return-outside-function)
zadanie2.py:13:0: W0101: Unreachable code (unreachable)
zadanie2.py:11:7: E0602: Undefined variable 'output' (undefined-variable)
zadanie2.py:13:3: E0602: Undefined variable 'name' (undefined-variable)

-------------------------------------
Your code has been rated at -15.00/10
```
```
#поиск уязвимостей кода Python
from flask import Flask, request
import subprocess

app = Flask(name)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')
    cmd = 'nslookup ' + hostname
    output = subprocess.check_output(cmd, shell=True, text=True)
return output
if name == "main":
    app.run(debug=True)

#поиск уязвимостей с помощью Pylint

sergei@DESKTOP-BBCO7PU:~$ pylint zadanie1.py
************* Module zadanie1
zadanie1.py:13:0: C0304: Final newline missing (missing-final-newline)
zadanie1.py:1:0: C0114: Missing module docstring (missing-module-docstring)
zadanie1.py:4:12: E0602: Undefined variable 'name' (undefined-variable)
zadanie1.py:7:0: C0116: Missing function or method docstring (missing-function-docstring)
zadanie1.py:10:4: W0612: Unused variable 'output' (unused-variable)
zadanie1.py:11:0: E0104: Return outside function (return-outside-function)
zadanie1.py:12:0: W0101: Unreachable code (unreachable)
zadanie1.py:11:7: E0602: Undefined variable 'output' (undefined-variable)
zadanie1.py:12:3: E0602: Undefined variable 'name' (undefined-variable)
zadanie1.py:2:0: C0411: standard import "import subprocess" should be placed before "from flask import Flask, request" (wrong-import-order)

-------------------------------------
Your code has been rated at -16.00/10
```
## Моделированиe угроз
1. Компрометация узлов внутри ДМЗ.
2. Компрометация сетевого оборудования и переконфигурация устройств контроля доступа. 
3. Компрометация клиентов, входящих в ДМЗ сеть.
4. Обнаружение отдельных сегментов, протоколов, которым предоставлен доступ в рамках сети ДМЗ.
5. Компрометация сетевого оборудования.
![DFD](https://github.com/sergei797/test-assignment/blob/main/test-dfd.png)

