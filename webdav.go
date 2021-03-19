package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	stdpath "path"
	"sync"
	"time"

	"golang.org/x/net/webdav"
	"golang.org/x/net/xsrftoken"

	"upspin.io/client"
	"upspin.io/errors"
	"upspin.io/path"
	"upspin.io/upspin"

	_ "upspin.io/transports"
)

const unixPermissions = 0700

// fileInfo implements os.FileInfo, which is used by the webdav package.
type fileInfo struct{ *upspin.DirEntry }

func (fi *fileInfo) Name() string       { return stdpath.Base(string(fi.DirEntry.Name)) }
func (fi *fileInfo) ModTime() time.Time { return fi.Time.Go() }
func (fi *fileInfo) Size() int64 {
	// DirEntry.Size() returns an error if blocks are not contiguous or a block size is
	// negative. Not much we can do to show that through webdav so just return whatever
	// size we get and disregard the error.
	size, _ := fi.DirEntry.Size()
	return size
}
func (fi *fileInfo) Mode() fs.FileMode {
	mode := os.FileMode(unixPermissions)
	if fi.DirEntry.IsDir() {
		mode = mode | fs.ModeDir
	}
	// TODO links?
	return mode
}
func (fi *fileInfo) Sys() interface{} { return nil }

// TODO: add fileInfo.ETag(). Perhaps DirEntry.Sequence could work as an ETag?

// file implements webdav.File.
type file struct {
	upspin.File // ReadWriteSeekCloser
	*upspin.DirEntry
	fs *filesystem
}

// Stat returns the DirEntry cached when the file was opened. It does not do a
// fresh lookup.
func (f *file) Stat() (fs.FileInfo, error) { return &fileInfo{f.DirEntry}, nil }

func (f *file) Close() error {
	if f.File != nil {
		return f.File.Close()
	}
	return nil
}

func (d *file) Readdir(count int) ([]fs.FileInfo, error) {
	des, err := d.fs.cli.Glob(upspin.AllFilesGlob(d.DirEntry.Name))
	if err != nil {
		return nil, err
	}
	if count <= 0 || count > len(des) {
		count = len(des)
	}
	fis := make([]fs.FileInfo, count)
	for i := 0; i < count; i++ {
		fis[i] = &fileInfo{des[i]}
	}
	return fis, nil
}

// root is a synthetic directory of known users. It implements both webdav.File os.FileInfo.
type root struct {
	sync.RWMutex
	userDirs map[upspin.UserName]bool
}

func (r *root) Readdir(count int) ([]fs.FileInfo, error) {
	r.RLock()
	defer r.RUnlock()

	var fis []fs.FileInfo
	for u := range r.userDirs {
		fis = append(fis, &fileInfo{&upspin.DirEntry{Name: upspin.PathName(u), Attr: upspin.AttrDirectory}})
	}
	if count > len(fis) {
		fis = fis[:count]
	}
	return fis, nil
}
func (r *root) Stat() (fs.FileInfo, error)                   { return r, nil }
func (r *root) Close() error                                 { return nil }
func (r *root) Read(data []byte) (n int, err error)          { return 0, webdav.ErrNotImplemented }
func (r *root) Seek(offset int64, whence int) (int64, error) { return 0, webdav.ErrNotImplemented }
func (r *root) Write(p []byte) (n int, err error)            { return 0, webdav.ErrNotImplemented }
func (r *root) Name() string                                 { return "" }
func (r *root) IsDir() bool                                  { return true }
func (r *root) ModTime() time.Time                           { return time.Time{} }
func (r *root) Size() int64                                  { return 0 }
func (r *root) Mode() fs.FileMode                            { return os.FileMode(unixPermissions) | fs.ModeDir }
func (r *root) Sys() interface{}                             { return nil }

func (r *root) addUserDir(name upspin.UserName) {
	r.Lock()
	r.userDirs[name] = true
	r.Unlock()
}

// filesystem implements a webdav.FileSystem backed by Upspin.
type filesystem struct {
	cfg  upspin.Config
	cli  upspin.Client
	key  string          // key to prevent request forgery; static for server's lifetime.
	dav  *webdav.Handler // The webdav http.Handler.
	root *root           // The root directory, which lists known users.
}

func newFilesystem(cfg upspin.Config) (*filesystem, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	fs := &filesystem{
		cfg:  cfg,
		cli:  client.New(cfg),
		key:  fmt.Sprintf("%x", key),
		root: &root{userDirs: map[upspin.UserName]bool{}},
	}

	fs.root.addUserDir(cfg.UserName())
	fs.dav = &webdav.Handler{
		Prefix:     "/", // Strip leading "/" to get upspin paths.
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
	}

	return fs, nil
}

func (fs *filesystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	_, err := fs.cli.MakeDirectory(upspin.PathName(name))
	return err
}

func (fs *filesystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if name == "" {
		return fs.root, nil
	}

	// The webdav package will open files as read-only for GET, or read-write with the create
	// and truncate flags for PUT. This gives it similar semantics to upspin's Open() and Create().

	switch flag {
	case os.O_RDONLY: // WebDAV GET.
		de, err := fs.cli.Lookup(upspin.PathName(name), true)
		if errors.Is(errors.NotExist, err) {
			return nil, os.ErrNotExist
		}
		if err != nil {
			return nil, err
		}
		if de.IsDir() {
			return &file{DirEntry: de, fs: fs}, nil
		}
		f, err := fs.cli.Open(upspin.PathName(name))
		if errors.Is(errors.NotExist, err) {
			return nil, os.ErrNotExist
		}
		if err != nil {
			return nil, err
		}
		return &file{File: f, DirEntry: de, fs: fs}, nil
	case os.O_RDWR | os.O_CREATE | os.O_TRUNC: // WebDAV PUT.
		f, err := fs.cli.Create(upspin.PathName(name))
		if err != nil {
			return nil, err
		}
		return &file{File: f, DirEntry: &upspin.DirEntry{Name: upspin.PathName(name)}, fs: fs}, nil
	}
	return nil, errors.E(errors.Invalid, "invalid open flag")
}

func (fs *filesystem) RemoveAll(ctx context.Context, name string) error {
	de, err := fs.cli.Lookup(upspin.PathName(name), false)
	if errors.Is(errors.NotExist, err) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	return fs.removeAll(de)
}

func (fs *filesystem) removeAll(de *upspin.DirEntry) error {
	if de.IsDir() {
		des, err := fs.cli.Glob(upspin.AllFilesGlob(de.Name))
		if err != nil {
			return err
		}
		for _, e := range des {
			fs.removeAll(e)
		}
	}
	return fs.cli.Delete(de.Name)
}

func (fs *filesystem) Rename(ctx context.Context, oldName, newName string) error {
	_, err := fs.cli.Rename(upspin.PathName(oldName), upspin.PathName(newName))
	return err
}

func (fs *filesystem) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	if name == "" {
		return fs.root, nil
	}
	p, err := path.Parse(upspin.PathName(name))
	if err != nil {
		return nil, os.ErrNotExist
	}

	// TODO don't look up macOS resource fork files ("._user@example.com") for known users

	de, err := fs.cli.Lookup(p.Path(), true)
	if errors.Is(errors.NotExist, err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if p.IsRoot() {
		fs.root.addUserDir(p.User())
	}
	return &fileInfo{de}, nil
}

// ServeHTTP validates and, if needed, generates csrf tokens before handing
// off to webdav.Handler.
//
// The goal is to allow localhost connections without passwords. The function isLocal()
// ensures we only listen on localhost. On its own, this is insecure since any website
// can use a resource on localhost and browsers will happily fetch it, e.g.
// <img src="http://localhost/augie@upspin.io/Images/Augie/smaller.jpg" />.
// So, in addition, we require a token in a SameSite=strict cookie. This tells browsers
// to only use the cookie if the origin is localhost, so mounting http://localhost/ using
// WebDAV or browsing to http://localhost/augie@upspin.io/Images/Augie/smaller.jpg
// directly works, but references from other sites don't.
//
// TODO: This feels too easy. Cross-origin requests are hairy and I'm sure I missed something.
//   - We can print fs.key on startup and require it as the basic auth password just to be
//     safe. That makes it safer on multi-user systems too. But copying and pasting a key
//     is inconvenient.
//   - We can also verify the connection is from the same user running this:
//       https://pkg.go.dev/github.com/perkeep/perkeep/pkg/httputil#IsLocalhost
func (fs *filesystem) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("csrf-token")
	if err == nil && cookie != nil &&
		xsrftoken.Valid(cookie.Value, fs.key, "", "") {
		// Token is valid, pass the request through.
		fs.dav.ServeHTTP(rw, r)
		return
	}

	// There's no valid token. We need to issue one.

	// First we check that the Origin header, if set, is localhost. Browsers set this in
	// the preflight request for cross-origin requests.
	if o := r.Header.Get("Origin"); o != "" && isLocal(o) != nil {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}

	// It is not enough to check Origin header alone, since browsers don't set it on "simple
	// requests", such as GET. So we restrict this to OPTIONS requests. Because:
	// 1. They aren't mutating,
	// 2. all WebDAV clients start with them,
	// 3. and if a browser *somehow* sent us a cross-origin request without an Origin header,
	//    OPTIONS leak limited information. Namely, only whether a path exists, and whether
	//    it's a file or a directory.
	if r.Method != http.MethodOptions {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     "csrf-token",
		Value:    xsrftoken.Generate(fs.key, "", ""),
		SameSite: http.SameSiteStrictMode,
	})
	fs.dav.ServeHTTP(rw, r)
}
