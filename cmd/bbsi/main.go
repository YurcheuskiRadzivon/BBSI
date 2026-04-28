package main

import (
	"log"
	"net/http"
	"os"

	"BBSI/internal/api"
	"BBSI/internal/crypto"
	"BBSI/internal/dag"
	"BBSI/internal/db"
)

func main() {
	dbDir := os.Getenv("BBSI_DB")
	if dbDir == "" {
		dbDir = "db"
	}
	database, err := db.Open(dbDir)
	if err != nil {
		log.Fatal(err)
	}
	keys, err := crypto.LoadOrCreateAuthorityKeys(database.Dir)
	if err != nil {
		log.Fatalf("ключи эмитентов: %v", err)
	}
	store, err := dag.NewStore(keys, database)
	if err != nil {
		log.Fatal(err)
	}
	srv := api.NewServer(store, keys, database)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("BBSI хэшчейн (DAG), БД: %s — http://localhost%s", dbDir, addr)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}
