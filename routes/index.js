var utils = require('../utils');
var mongoose = require('mongoose');
var Todo = mongoose.model('Todo');
var User = mongoose.model('User');
// TODO:
var hms = require('humanize-ms');
var ms = require('ms');
var streamBuffers = require('stream-buffers');
var readline = require('readline');
var moment = require('moment');
var exec = require('child_process').exec;
var validator = require('validator');

// zip-slip
var fileType = require('file-type');
var AdmZip = require('adm-zip');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// prototype-pollution
var _ = require('lodash');

exports.index = function (req, res, next) {
  Todo.
    find({}).
    sort('-updated_at').
    exec(function (err, todos) {
      if (err) return next(err);

      res.render('index', {
        title: 'Patch TODO List',
        subhead: 'Vulnerabilities at their best',
        todos: todos,
      });
    });
};

exports.loginHandler = function (req, res, next) {
  if (validator.isEmail(req.body.username)) {
    User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
      if (users.length > 0) {
        const redirectPage = req.body.redirectPage
        const session = req.session
        const username = req.body.username
        return adminLoginSuccess(redirectPage, session, username, res)
      } else {
        return res.status(401).send()
      }
    });
  } else {
    return res.status(401).send()
  }
};

function adminLoginSuccess(redirectPage, session, username, res) {
  session.loggedIn = 1

  // Log the login action for audit
  console.log(`User logged in: ${username}`)

  if (redirectPage) {
      return res.redirect(redirectPage)
  } else {
      return res.redirect('/admin')
  }
}

exports.login = function (req, res, next) {
  return res.render('admin', {
    title: 'Admin Access',
    granted: false,
    redirectPage: req.query.redirectPage
  });
};

exports.admin = function (req, res, next) {
  return res.render('admin', {
    title: 'Admin Access Granted',
    granted: true,
  });
};

exports.get_account_details = function(req, res, next) {
  // @TODO need to add a database call to get the profile from the database
  // and provide it to the view to display
  const profile = {}
 	return res.render('account.hbs', profile)
}

exports.save_account_details = function(req, res, next) {
  // get the profile details from the JSON
	const profile = req.body
  // validate the input
  if (validator.isEmail(profile.email, { allow_display_name: true })
    // allow_display_name allows us to receive input as:
    // Display Name <email-address>
    // which we consider valid too
    && validator.isMobilePhone(profile.phone, 'he-IL')
    && validator.isAscii(profile.firstname)
    && validator.isAscii(profile.lastname)
    && validator.isAscii(profile.country)
  ) {
    // trim any extra spaces on the right of the name
    profile.firstname = validator.rtrim(profile.firstname)
    profile.lastname = validator.rtrim(profile.lastname)

    // render the view
    return res.render('account.hbs', profile)
  } else {
    // if input validation fails, we just render the view as is
    console.log('error in form details')
    return res.render('account.hbs')
  }
}

exports.isLoggedIn = function (req, res, next) {
  if (req.session.loggedIn === 1) {
    return next()
  } else {
    return res.redirect('/')
  }
}

exports.logout = function (req, res, next) {
  req.session.loggedIn = 0
  req.session.destroy(function() { 
    return res.redirect('/')  
  })
}

function parse(todo) {
  var t = todo;

  var remindToken = ' in ';
  var reminder = t.toString().indexOf(remindToken);
  if (reminder > 0) {
    var time = t.slice(reminder + remindToken.length);
    time = time.replace(/\n$/, '');

    var period = hms(time);

    console.log('period: ' + period);

    // remove it
    t = t.slice(0, reminder);
    if (typeof period != 'undefined') {
      t += ' [' + ms(period) + ']';
    }
  }
  return t;
}

exports.create = function (req, res, next) {
  // console.log('req.body: ' + JSON.stringify(req.body));

  var item = req.body.content;
  var imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
  if (typeof (item) == 'string' && item.match(imgRegex)) {
    var url = item.match(imgRegex)[1];
    console.log('found img: ' + url);

    exec('identify ' + url, function (err, stdout, stderr) {
      console.log(err);
      if (err !== null) {
        console.log('Error (' + err + '):' + stderr);
      }
    });

  } else {
    item = parse(item);
  }

  new Todo({
    content: item,
    updated_at: Date.now(),
  }).save(function (err, todo, count) {
    if (err) return next(err);

    /*
    res.setHeader('Data', todo.content.toString('base64'));
    res.redirect('/');
    */

    res.setHeader('Location', '/');
    res.status(302).send(todo.content.toString('base64'));

    // res.redirect('/#' + todo.content.toString('base64'));
  });
};

exports.destroy = function (req, res, next) {
  Todo.findById(req.params.id, function (err, todo) {

    try {
      todo.remove(function (err, todo) {
        if (err) return next(err);
        res.redirect('/');
      });
    } catch (e) {
    }
  });
};

exports.edit = function (req, res, next) {
  Todo.
    find({}).
    sort('-updated_at').
    exec(function (err, todos) {
      if (err) return next(err);

      res.render('edit', {
        title: 'TODO',
        todos: todos,
        current: req.params.id
      });
    });
};

exports.update = function (req, res, next) {
  Todo.findById(req.params.id, function (err, todo) {

    todo.content = req.body.content;
    todo.updated_at = Date.now();
    todo.save(function (err, todo, count) {
      if (err) return next(err);

      res.redirect('/');
    });
  });
};

// ** express turns the cookie key to lowercase **
exports.current_user = function (req, res, next) {

  next();
};

function isBlank(str) {
  return (!str || /^\s*$/.test(str));
}

exports.import = function (req, res, next) {
  if (!req.files) {
    res.send('No files were uploaded.');
    return;
  }

  var importFile = req.files.importFile;
  
  // Enforce maximum file size (10MB)
  var MAX_FILE_SIZE = 10 * 1024 * 1024;
  if (importFile.size > MAX_FILE_SIZE) {
    res.status(413).send('File too large. Maximum size is 10MB.');
    return;
  }
  
  var data;
  var importedFileType = fileType(importFile.data);
  var zipFileExt = { ext: "zip", mime: "application/zip" };
  if (importedFileType === null) {
    importedFileType = { ext: "txt", mime: "text/plain" };
  }
  if (importedFileType["mime"] === zipFileExt["mime"]) {
    var zip;
    try {
      zip = AdmZip(importFile.data);
    } catch (err) {
      res.status(400).send('Invalid ZIP file.');
      return;
    }
    
    var zipEntries = zip.getEntries();
    
    // Enforce maximum number of entries to prevent resource exhaustion
    var MAX_ENTRIES = 100;
    if (zipEntries.length > MAX_ENTRIES) {
      res.status(400).send('ZIP file contains too many entries. Maximum is ' + MAX_ENTRIES + '.');
      return;
    }
    
    // Validate decompressed size and compression ratio to detect zip bombs
    var MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024; // 50MB
    var MAX_COMPRESSION_RATIO = 100;
    var totalCompressedSize = 0;
    var totalDecompressedSize = 0;
    
    for (var i = 0; i < zipEntries.length; i++) {
      var entry = zipEntries[i];
      totalCompressedSize += entry.header.compressedSize;
      totalDecompressedSize += entry.header.size;
      
      // Check individual entry size
      if (entry.header.size > MAX_DECOMPRESSED_SIZE) {
        res.status(400).send('ZIP entry too large. Maximum decompressed size is 50MB.');
        return;
      }
      
      // Validate entry name to prevent path traversal
      var entryName = entry.entryName;
      if (entryName.indexOf('..') !== -1 || entryName.indexOf('/') === 0 || entryName.indexOf('\\') === 0) {
        res.status(400).send('Invalid entry name in ZIP file.');
        return;
      }
    }
    
    // Check total decompressed size
    if (totalDecompressedSize > MAX_DECOMPRESSED_SIZE) {
      res.status(400).send('Total decompressed size exceeds limit of 50MB.');
      return;
    }
    
    // Check compression ratio to detect zip bombs
    if (totalCompressedSize > 0 && (totalDecompressedSize / totalCompressedSize) > MAX_COMPRESSION_RATIO) {
      res.status(400).send('Suspicious compression ratio detected. Possible zip bomb.');
      return;
    }
    
    // Create unique extraction directory per request to avoid conflicts
    var uniqueId = crypto.randomBytes(16).toString('hex');
    var extracted_path = "/tmp/extracted_files_" + uniqueId;
    
    try {
      // Ensure directory exists
      if (!fs.existsSync(extracted_path)) {
        fs.mkdirSync(extracted_path, { recursive: true });
      }
      
      zip.extractAllTo(extracted_path, true);
      
      // Read backup.txt from the extracted directory
      var backupPath = path.join(extracted_path, 'backup.txt');
      data = "No backup.txt file found";
      
      if (fs.existsSync(backupPath)) {
        try {
          data = fs.readFileSync(backupPath, 'ascii');
        } catch (err) {
          console.error('Error reading backup.txt:', err);
        }
      }
      
      // Clean up extracted files
      try {
        var rimraf = function(dir_path) {
          if (fs.existsSync(dir_path)) {
            fs.readdirSync(dir_path).forEach(function(entry) {
              var entry_path = path.join(dir_path, entry);
              if (fs.lstatSync(entry_path).isDirectory()) {
                rimraf(entry_path);
              } else {
                fs.unlinkSync(entry_path);
              }
            });
            fs.rmdirSync(dir_path);
          }
        };
        rimraf(extracted_path);
      } catch (cleanupErr) {
        console.error('Error cleaning up extracted files:', cleanupErr);
      }
    } catch (err) {
      // Clean up on error
      try {
        if (fs.existsSync(extracted_path)) {
          var rimraf = function(dir_path) {
            if (fs.existsSync(dir_path)) {
              fs.readdirSync(dir_path).forEach(function(entry) {
                var entry_path = path.join(dir_path, entry);
                if (fs.lstatSync(entry_path).isDirectory()) {
                  rimraf(entry_path);
                } else {
                  fs.unlinkSync(entry_path);
                }
              });
              fs.rmdirSync(dir_path);
            }
          };
          rimraf(extracted_path);
        }
      } catch (cleanupErr) {
        console.error('Error cleaning up after extraction failure:', cleanupErr);
      }
      res.status(500).send('Error extracting ZIP file.');
      return;
    }
  } else {
    // Enforce maximum size for text files
    var MAX_TEXT_SIZE = 1 * 1024 * 1024; // 1MB
    if (importFile.size > MAX_TEXT_SIZE) {
      res.status(413).send('Text file too large. Maximum size is 1MB.');
      return;
    }
    data = importFile.data.toString('ascii');
  }
  
  var lines = data.split('\n');
  
  // Limit number of lines to process
  var MAX_LINES = 1000;
  if (lines.length > MAX_LINES) {
    res.status(400).send('Too many lines to import. Maximum is ' + MAX_LINES + '.');
    return;
  }
  
  lines.forEach(function (line) {
    var parts = line.split(',');
    var what = parts[0];
    console.log('importing ' + what);
    var when = parts[1];
    var locale = parts[2];
    var format = parts[3];
    var item = what;
    if (!isBlank(what)) {
      if (!isBlank(when) && !isBlank(locale) && !isBlank(format)) {
        console.log('setting locale ' + parts[1]);
        moment.locale(locale);
        var d = moment(when);
        console.log('formatting ' + d);
        item += ' [' + d.format(format) + ']';
      }

      new Todo({
        content: item,
        updated_at: Date.now(),
      }).save(function (err, todo, count) {
        if (err) return next(err);
        console.log('added ' + todo);
      });
    }
  });

  res.redirect('/');
};

exports.about_new = function (req, res, next) {
  console.log(JSON.stringify(req.query));
  return res.render("about_new.dust",
    {
      title: 'Patch TODO List',
      subhead: 'Vulnerabilities at their best',
      device: req.query.device
    });
};

// Prototype Pollution

///////////////////////////////////////////////////////////////////////////////
// In order of simplicity we are not using any database. But you can write the
// same logic using MongoDB.
const users = [
  // You know password for the user.
  { name: 'user', password: 'pwd' },
  // You don't know password for the admin.
  { name: 'admin', password: Math.random().toString(32), canDelete: true },
];

let messages = [];
let lastId = 1;

function findUser(auth) {
  return users.find((u) =>
    u.name === auth.name &&
    u.password === auth.password);
}
///////////////////////////////////////////////////////////////////////////////

exports.chat = {
  get(req, res) {
    res.send(messages);
  },
  add(req, res) {
    const user = findUser(req.body.auth || {});

    if (!user) {
      res.status(403).send({ ok: false, error: 'Access denied' });
      return;
    }

    const message = {
      // Default message icon. Cen be overwritten by user.
      icon: '👋',
    };

    _.merge(message, req.body.message, {
      id: lastId++,
      timestamp: Date.now(),
      userName: user.name,
    });

    messages.push(message);
    res.send({ ok: true });
  },
  delete(req, res) {
    const user = findUser(req.body.auth || {});

    if (!user || !user.canDelete) {
      res.status(403).send({ ok: false, error: 'Access denied' });
      return;
    }

    messages = messages.filter((m) => m.id !== req.body.messageId);
    res.send({ ok: true });
  }
};
