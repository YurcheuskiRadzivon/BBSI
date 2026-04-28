package db

import (
	"errors"
	"time"
)

// ErrDocumentNotInRegistry — нет строки в documents.json для заданного document_id.
var ErrDocumentNotInRegistry = errors.New("документ отсутствует в реестре documents.json")

// UpsertDocument добавляет или обновляет запись по document_id.
func UpsertDocument(database *Database, doc StoredDocument) error {
	if database == nil {
		return nil
	}
	var f DocumentsFile
	_ = database.ReadJSON(FileDocuments, &f)
	doc.UpdatedAtUnix = time.Now().Unix()
	found := -1
	for i, x := range f.Documents {
		if x.DocumentID == doc.DocumentID {
			found = i
			break
		}
	}
	if found >= 0 {
		f.Documents[found] = doc
	} else {
		f.Documents = append(f.Documents, doc)
	}
	return database.WriteJSON(FileDocuments, &f)
}

// UpsertDocumentLastAction обновляет ссылку на последнюю транзакцию в журнале (issue или revoke).
func UpsertDocumentLastAction(database *Database, documentID, lastTxID, lastAction string) error {
	if database == nil {
		return nil
	}
	var f DocumentsFile
	if err := database.ReadJSON(FileDocuments, &f); err != nil {
		return err
	}
	for i := range f.Documents {
		if f.Documents[i].DocumentID != documentID {
			continue
		}
		f.Documents[i].LastTxID = lastTxID
		f.Documents[i].LastAction = lastAction
		f.Documents[i].UpdatedAtUnix = time.Now().Unix()
		return database.WriteJSON(FileDocuments, &f)
	}
	return ErrDocumentNotInRegistry
}
