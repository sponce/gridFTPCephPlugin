/******************************************************************************
 * posix layer around the CEPH radosstriper interface
 *
 * @author Sebastien Ponce, sebastien.ponce@cern.ch
 *****************************************************************************/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <radosstriper/libradosstriper.hpp>
#include <map>
#include <stdexcept>
#include <string>
#include <sstream>
#include <sys/xattr.h>
#include <time.h>
#include <limits>
#include <ceph_posix.h>

/// small structs to store file metadata
struct CephFile {
  std::string name;
  std::string pool;
  std::string userId;
  unsigned int nbStripes;
  unsigned long long stripeUnit;
  unsigned long long objectSize;
};

struct CephFileRef : CephFile {
  int flags;
  mode_t mode;
  unsigned long long offset;
};

/// small struct for directory listing
struct DirIterator {
  librados::ObjectIterator m_iterator;
  librados::IoCtx *m_ioctx;
};

/// global variables holding stripers and ioCtxs for each ceph pool plus the cluster object
std::map<std::string, libradosstriper::RadosStriper*> g_radosStripers;
std::map<std::string, librados::IoCtx*> g_ioCtx;
librados::Rados* g_cluster = 0;
/// global variable holding a map of file descriptor to file reference
std::map<unsigned int, CephFileRef> g_fds;
/// global variable holding a list of files currently opened for write
std::multiset<std::string> g_filesOpenForWrite;
/// global variable remembering the next available file descriptor
unsigned int g_nextCephFd = 0;
/// global variable containing defaults for CephFiles
CephFile g_defaultParams = { "",
                             "default",        // default pool
                             "admin",          // default user
                             1,                // default nbStripes
                             4 * 1024 * 1024,  // default stripeUnit : 4 MB
                             4 * 1024 * 1024}; // default objectSize : 4 MB

std::string g_defaultUserId = "admin";
std::string g_defaultPool = "default";

/// global variable for the log function
static void (*g_logfunc) (char *, va_list argp) = 0;

static void logwrapper(char* format, ...) {
  if (0 == g_logfunc) return;
  va_list arg;
  va_start(arg, format);
  (*g_logfunc)(format, arg);
  va_end(arg);
}

/// simple integer parsing, to be replaced by std::stoll when C++11 can be used
static unsigned long long int stoull(const std::string &s) {
  char* end;
  errno = 0;
  unsigned long long int res = strtoull(s.c_str(), &end, 10);
  if (0 != *end) {
    throw std::invalid_argument(s);
  }
  if (ERANGE == errno) {
    throw std::out_of_range(s);
  }
  return res;
}

/// simple integer parsing, to be replaced by std::stoi when C++11 can be used
static unsigned int stoui(const std::string &s) {
  char* end;
  errno = 0;
  unsigned long int res = strtoul(s.c_str(), &end, 10);
  if (0 != *end) {
    throw std::invalid_argument(s);
  }
  if (ERANGE == errno || res > std::numeric_limits<unsigned int>::max()) {
    throw std::out_of_range(s);
  }
  return (unsigned int)res;
}

/// fills the userId of a ceph file struct from a string
/// returns position of first character after the userId
static int fillCephUserId(const std::string &params, CephFile &file) {
  // default
  file.userId = g_defaultParams.userId;
  // parsing
  size_t atPos = params.find('@');
  if (std::string::npos != atPos) {
    file.userId = params.substr(0, atPos);
    return atPos+1;
  } else {
    return 0;
  }
}

/// fills the pool of a ceph file struct from a string
/// returns position of first character after the pool
static int fillCephPool(const std::string &params, unsigned int offset, CephFile &file) {
  // default
  file.pool = g_defaultParams.pool;
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {
    if (params.size() != offset) {
      file.pool = params.substr(offset);
    }
    return params.size();
  } else {
    file.pool = params.substr(offset, comPos-offset);
    return comPos+1;
  }
}

/// fills the nbStriped of a ceph file struct from a string
/// returns position of first character after the nbStripes
// this may raise std::invalid_argument and std::out_of_range
static int fillCephNbStripes(const std::string &params, unsigned int offset, CephFile &file) {
  // default
  file.nbStripes = g_defaultParams.nbStripes;
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {
    if (params.size() != offset) {
      file.nbStripes = stoui(params.substr(offset));
    }
    return params.size();
  } else {
    file.nbStripes = stoui(params.substr(offset, comPos-offset));
    return comPos+1;
  }
}

/// fills the stripeUnit of a ceph file struct from a string
/// returns position of first character after the stripeUnit
// this may raise std::invalid_argument and std::out_of_range
static int fillCephStripeUnit(const std::string &params, unsigned int offset, CephFile &file) {
  // default
  file.stripeUnit = g_defaultParams.stripeUnit;
  // parsing
  size_t comPos = params.find(',', offset);
  if (std::string::npos == comPos) {
    if (params.size() != offset) {
      file.stripeUnit = stoull(params.substr(offset));
    }
    return params.size();
  } else {
    file.stripeUnit = stoull(params.substr(offset, comPos-offset));
    return comPos+1;
  }
}

/// fills the objectSize of a ceph file struct from a string
/// returns position of first character after the objectSize
// this may raise std::invalid_argument and std::out_of_range
static void fillCephObjectSize(const std::string &params, unsigned int offset, CephFile &file) {
  // default
  file.objectSize = g_defaultParams.objectSize;
  // parsing
  if (params.size() != offset) {
    file.objectSize = stoull(params.substr(offset));
  }
}

/// fill the parameters of a ceph file struct (all but name) from a string
/// see fillCephFile for the detailed syntax
void fillCephFileParams(const std::string &params, CephFile &file) {
  // parse the params one by one
  unsigned int afterUser = fillCephUserId(params, file);
  unsigned int afterPool = fillCephPool(params, afterUser, file);
  unsigned int afterNbStripes = fillCephNbStripes(params, afterPool, file);
  unsigned int afterStripeUnit = fillCephStripeUnit(params, afterNbStripes, file);
  fillCephObjectSize(params, afterStripeUnit, file);
}

/// sets the default userId, pool and file layout
/// syntax is [user@]pool[,nbStripes[,stripeUnit[,objectSize]]]
/// may throw std::invalid_argument or std::out_of_range in case of error
void ceph_posix_set_defaults(const char* value) {
  if (value) {
    CephFile newdefault;
    fillCephFileParams(value, newdefault);
    g_defaultParams = newdefault;
  }
}

/// fill a ceph file struct from a path
void fillCephFile(const char *path, CephFile &file) {
  // Syntax of the given path is :
  //   [[userId@]pool[,nbStripes[,stripeUnit[,objectSize]]]:]<actual path>
  // for the missing parts, defaults are applied. These defaults are
  // initially set to 'admin', 'default', 1, 4MB and 4MB
  // but can be changed via a call to ceph_posix_set_defaults
  std::string spath = path;
  size_t colonPos = spath.find(':');
  if (std::string::npos == colonPos) {
    file.name = spath;
    fillCephFileParams("", file);
  } else {
    file.name = spath.substr(colonPos+1);
    fillCephFileParams(spath.substr(0, colonPos), file);
  }
}

static CephFile getCephFile(const char *path) {
  CephFile file;
  fillCephFile(path, file);
  return file;
}

static CephFileRef getCephFileRef(const char *path, int flags,
                                  mode_t mode, unsigned long long offset) {
  CephFileRef fr;
  fillCephFile(path, fr);
  fr.flags = flags;
  fr.mode = mode;
  fr.offset = 0;
  return fr;
}

static libradosstriper::RadosStriper* getRadosStriper(const CephFile& file) {
  std::stringstream ss;
  ss << file.userId << '@' << file.pool << ',' << file.nbStripes << ','
     << file.stripeUnit << ',' << file.objectSize;
  std::string userAtPool = ss.str();
  std::map<std::string, libradosstriper::RadosStriper*>::iterator it =
    g_radosStripers.find(userAtPool);
  if (it == g_radosStripers.end()) {
    // we need to create a new radosStriper
    // Do we already have a cluster
    if (0 == g_cluster) {
      // create connection to cluster
      g_cluster = new librados::Rados;
      if (0 == g_cluster) {
        return 0;
      }
      int rc = g_cluster->init(file.userId.c_str());
      if (rc) {
        delete g_cluster;
        g_cluster = 0;
        return 0;
      }
      rc = g_cluster->conf_read_file(NULL);
      if (rc) {
        g_cluster->shutdown();
        delete g_cluster;
        g_cluster = 0;
        return 0;
      }
      g_cluster->conf_parse_env(NULL);
      rc = g_cluster->connect();
      if (rc) {
        g_cluster->shutdown();
        delete g_cluster;
        g_cluster = 0;
        return 0;
      }
    }
    // create IoCtx for our pool
    librados::IoCtx *ioctx = new librados::IoCtx;
    if (0 == ioctx) {
      g_cluster->shutdown();
      delete g_cluster;
      return 0;
    }
    int rc = g_cluster->ioctx_create(file.pool.c_str(), *ioctx);
    if (rc != 0) {
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      delete ioctx;
      return 0;
    }
    // create RadosStriper connection
    libradosstriper::RadosStriper *striper = new libradosstriper::RadosStriper;
    if (0 == striper) {
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    rc = libradosstriper::RadosStriper::striper_create(*ioctx, striper);
    if (rc != 0) {
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    // setup layout
    rc = striper->set_object_layout_stripe_count(file.nbStripes);
    if (rc != 0) {
      logwrapper((char*)"getRadosStriper : invalid nbStripes %d", file.nbStripes);
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    rc = striper->set_object_layout_stripe_unit(file.stripeUnit);
    if (rc != 0) {
      logwrapper((char*)"getRadosStriper : invalid stripeUnit %d (must be non0, multiple of 64K)", file.stripeUnit);
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    rc = striper->set_object_layout_object_size(file.objectSize);
    if (rc != 0) {
      logwrapper((char*)"getRadosStriper : invalid objectSize %d (must be non 0, multiple of stripe_unit)", file.objectSize);
      delete striper;
      delete ioctx;
      g_cluster->shutdown();
      delete g_cluster;
      g_cluster = 0;
      return 0;
    }
    g_ioCtx.insert(std::pair<std::string, librados::IoCtx*>(userAtPool, ioctx));    
    it = g_radosStripers.insert(std::pair<std::string, libradosstriper::RadosStriper*>
                                (userAtPool, striper)).first;
  }
  return it->second;
}

static librados::IoCtx* getIoCtx(const CephFile& file) {
  libradosstriper::RadosStriper *striper = getRadosStriper(file);
  if (0 == striper) {
    return 0;
  }
  return g_ioCtx[file.pool];
}

void ceph_posix_disconnect_all() {
  for (std::map<std::string, libradosstriper::RadosStriper*>::iterator it =
         g_radosStripers.begin();
       it != g_radosStripers.end();
       it++) {
    delete it->second;
  }
  g_radosStripers.clear();
  for (std::map<std::string, librados::IoCtx*>::iterator it = g_ioCtx.begin();
       it != g_ioCtx.end();
       it++) {
    delete it->second;
  }
  g_ioCtx.clear();
  delete g_cluster;
}

extern "C" {

  void ceph_posix_set_logfunc(void (*logfunc) (char *, va_list argp)) {
    g_logfunc = logfunc;
  };

  int ceph_posix_open(const char *pathname, int flags, mode_t mode) {
    logwrapper((char*)"ceph_open : fd %d associated to %s", g_nextCephFd, pathname);
    CephFileRef fr = getCephFileRef(pathname, flags, mode, 0);
    g_fds[g_nextCephFd] = fr;
    g_nextCephFd++;
    if (flags & O_WRONLY) {
      g_filesOpenForWrite.insert(fr.name);
    }
    return g_nextCephFd-1;
  }

  int ceph_posix_close(int fd) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      logwrapper((char*)"ceph_close: closed fd %d", fd);
      if (it->second.flags & O_WRONLY) {
        g_filesOpenForWrite.erase(g_filesOpenForWrite.find(it->second.name));
      }
      g_fds.erase(it);
      return 0;
    } else {
      return -EBADF;
    }
  }

  static off64_t lseek_compute_offset(CephFileRef &fr, off64_t offset, int whence) {
    switch (whence) {
    case SEEK_SET:
      fr.offset = offset;
      break;
    case SEEK_CUR:
      fr.offset += offset;
      break;
    default:
      return -EINVAL;
    }
    return 0;
  }

  off64_t ceph_posix_lseek64(int fd, off64_t offset, int whence) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
      logwrapper((char*)"ceph_lseek64: for fd %d, offset=%d, whence=%d", fd, offset, whence);
      return lseek_compute_offset(fr, offset, whence);
    } else {
      return -EBADF;
    }
  }

  ssize_t ceph_posix_write(int fd, const void *buf, size_t count) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
      logwrapper((char*)"ceph_write: for fd %d, count=%d", fd, count);
      if ((fr.flags & O_WRONLY) == 0) {
        return -EBADF;
      }
      libradosstriper::RadosStriper *striper = getRadosStriper(fr);
      if (0 == striper) {
        return -EINVAL;
      }
      ceph::bufferlist bl;
      bl.append((const char*)buf, count);
      int rc = striper->write(fr.name, bl, count, fr.offset);
      if (rc) return rc;
      fr.offset += count;
      return count;
    } else {
      return -EBADF;
    }
  }

  ssize_t ceph_posix_read(int fd, void *buf, size_t count) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
      logwrapper((char*)"ceph_read: for fd %d, count=%d", fd, count);
      if ((fr.flags & O_WRONLY) != 0) {
        return -EBADF;
      }
      libradosstriper::RadosStriper *striper = getRadosStriper(fr);
      if (0 == striper) {
        return -EINVAL;
      }
      ceph::bufferlist bl;
      int rc = striper->read(fr.name, &bl, count, fr.offset);
      if (rc < 0) return rc;
      bl.copy(0, rc, (char*)buf);
      fr.offset += rc;
      return rc;
    } else {
      return -EBADF;
    }
  }

  int ceph_posix_stat64(const char *pathname, struct stat64 *buf) {
    logwrapper((char*)"ceph_stat64 : %s", pathname);
    // minimal stat : only size and times are filled
    // atime, mtime and ctime are set all to the same value
    // mode is set arbitrarily to 0666
    libradosstriper::RadosStriper *striper = getRadosStriper(getCephFile(pathname));
    if (0 == striper) {
      return -EINVAL;
    }
    memset(buf, 0, sizeof(*buf));
    int rc = striper->stat(pathname, (uint64_t*)&(buf->st_size), &(buf->st_atime));
    if (rc != 0) {
      // for non existing file. Check that we did not open it for write recently
      // in that case, we return 0 size and current time
      if (-ENOENT == rc && g_filesOpenForWrite.find(pathname) != g_filesOpenForWrite.end()) {
        buf->st_size = 0;
        buf->st_atime = time(NULL);
      } else {
        return -rc;
      }
    }
    buf->st_mtime = buf->st_atime;
    buf->st_ctime = buf->st_atime;  
    buf->st_mode = 0666;
    return 0;
  }

  static ssize_t ceph_posix_internal_getxattr(const CephFile &file, const char* name,
                                              void* value, size_t size) {
    libradosstriper::RadosStriper *striper = getRadosStriper(file);
    if (0 == striper) {
      return -EINVAL;
    }
    ceph::bufferlist bl;
    int rc = striper->getxattr(file.name, name, bl);
    if (rc) {
      return -rc;
    }
    bl.copy(0, size, (char*)value);
    return 0;
  }  

  ssize_t ceph_posix_fgetxattr(int fd, const char* name,
                               void* value, size_t size) {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
      logwrapper((char*)"ceph_fgetxattr: fd %d name=%s", fd, name);
      return ceph_posix_internal_getxattr(fr, name, value, size);
    } else {
      return -EBADF;
    }
  }

  static ssize_t ceph_posix_internal_setxattr(const CephFile &file, const char* name,
                                              const void* value, size_t size, int flags) {
    libradosstriper::RadosStriper *striper = getRadosStriper(file);
    if (0 == striper) {
      return -EINVAL;
    }
    ceph::bufferlist bl;
    bl.append((const char*)value, size);
    int rc = striper->setxattr(file.name, name, bl);
    if (rc) {
      return -rc;
    }
    return 0;
  }

  int ceph_posix_fsetxattr(int fd,
                           const char* name, const void* value,
                           size_t size, int flags)  {
    std::map<unsigned int, CephFileRef>::iterator it = g_fds.find(fd);
    if (it != g_fds.end()) {
      CephFileRef &fr = it->second;
      logwrapper((char*)"ceph_fsetxattr: fd %d name=%s value=%s", fd, name, value);
      return ceph_posix_internal_setxattr(fr, name, value, size, flags);
    } else {
      return -EBADF;
    }
  }

} // extern "C"
