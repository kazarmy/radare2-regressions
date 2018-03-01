const co = require('co');
const colors = require('colors/safe');
const promisify = require('promisify-node');
const walk = require('walk').walk;
const fs = promisify('fs');
const jsdiff = require('diff');
const tmp = require('tmp');
const zlib = require('zlib');
const path = require('path');
const spawn = require('child_process').spawn;
const spawnSync = require('child_process').spawnSync;
const r2promise = require('r2pipe-promise');
const common = require('./common');

const timeoutFuzzed = 60 * 1000;

// support node < 8
if (!String.prototype.padStart) {
  String.prototype.padStart = function padStart (targetLength, padString) {
    targetLength = targetLength >> 0; // floor if number or convert non-number to 0;
    padString = String(padString || ' ');
    if (this.length > targetLength) {
      return String(this);
    } else {
      targetLength = targetLength - this.length;
      if (targetLength > padString.length) {
        padString += padString.repeat(targetLength / padString.length); // append to original to ensure we are longer than needed
      }
      return padString.slice(0, targetLength) + String(this);
    }
  };
}

// set this to false to avoid creating files
let useScript = true;

/* radare2 binary name */
const r2bin = 'radare2';

class NewRegressions {
  constructor (argv, cb) {
    this.argv = argv;
    this.queue = [];
    this.report = {
      total: 0,
      success: 0,
      failed: 0,
      broken: 0,
      fixed: 0,
      totaltime: 0
    };
    useScript = !argv.c;
    this.verbose = this.argv.verbose || this.argv.v;
    this.interactive = this.argv.interactive || this.argv.i;
    this.promises = [];
    // reduce startup times of r2
    process.env.RABIN2_NOPLUGINS = 1;
    process.env.RASM2_NOPLUGINS = 1;
    process.env.R2_NOPLUGINS = 1;
    r2promise.open('-').then(r2 => {
      this.r2 = r2;
      cb(null, r2);
    }).catch(e => {
      cb(e);
    });
    this.start = new Date();
  }

  callbackFromPath (from) {
    for (let row of [
      [path.join('db', 'anal'), this.runTest],
      [path.join('db', 'cmd'), this.runTest],
      [path.join('db', 'bin'), this.runTestBin]
    ]) {
      const [txt, cb] = row;
      if (from.indexOf(txt) !== -1) {
        return cb;
      }
    }
    return null;
  }

  quit () {
    const promise = this.r2 !== null
      ? this.r2.quit()
      : new Promise(resolve => resolve());
    this.r2 = null;
    return promise;
  }

  runTestAsm (test, cb) {
    const self = this;
    return new Promise((resolve, reject) => {
      try {
        co(function * () {
          try {
            if (test.args) {
              self.r2.cmd(test.args);
            }
            test.stdout = yield self.r2.cmd(test.cmd);
            return resolve(cb(test));
          } catch (e) {
            return reject(e);
          }
        });
      } catch (e) {
        console.error(e);
        reject(e);
      }
    });
  }

  runTestBin (test, cb) {
    const testPath = test.path;
    return new Promise((resolve, reject) => {
      const promises = [];
      const walker = walk(test.path, {followLinks: false});
      walker.on('file', (root, stat, next) => {
        const newTest = Object.assign({}, test);
        newTest.path = path.join(testPath, stat.name);
        promises.push(this.runTestBinFile(newTest, cb));
        next();
      });
      walker.on('end', () => {
        Promise.all(promises).then(res => {
          console.log('Bins Done');
          resolve();
        }).catch(reject);
      });
    });
  }

  runTestBinFile (test, cb) {
    return new Promise((resolve, reject) => {
      try {
        co(function * () {
          const args = [
            '-escr.utf8=0',
            '-escr.color=0',
            '-c',
            '?e init',
            '-qcq',
            '-A', // configurable to AAA, or just A somehow
            test.path
          ];
          test.birth = null;
          const child = spawn(r2bin, args);
          child.stdout.on('data', data => {
            // console.log(data.toString());
            if (test.birth === null) {
              test.birth = new Date();
            }
          });
          child.stderr.on('data', data => {
          //  console.error(data.toString());
          });
          child.on('close', data => {
            test.death = new Date();
            test.lifetime = test.death - test.birth;
            return resolve(cb(test));
          });
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  runTestFuzz (test, cb) {
    return new Promise((resolve, reject) => {
      try {
        co(function * () {
          const args = ['-c', '?e init', '-qcq', '-A', test.path];
          test.birth = new Date();
          const child = spawnSync(r2bin, args, {timeout: timeoutFuzzed});
          test.death = new Date();
          test.lifetime = test.death - test.birth;
          if (child.error) {
            test.expectErr = 'N';
            test.stderr = 'X';
            test.spawnArgs = args;
            test.cmdScript = '';
            return reject(cb(test));
          } else {
            return resolve(cb(test));
          }
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  runTest (test, cb) {
    return new Promise((resolve, reject) => {
      if (this.argv.l) {
        console.log(test.from.replace('db/', ''), test.name);
        return resolve();
      }
      co(function * () {
        const args = [
          '-escr.utf8=0',
          '-escr.color=0',
          '-N',
          '-Q'
        ];
        // append custom r2 args
        if (test.args && test.args.length > 0) {
          args.push(...test.args.split(' '));
        }
        try {
          if (useScript) {
            // TODO much slower than just using -c
            test.tmpScript = yield createTemporaryFile();
            // TODO use yield here
            yield fs.writeFile(test.tmpScript, test.cmdScript);
            args.push('-i', test.tmpScript);
          } else {
            if (!test.cmds && test.cmdScript) {
              test.cmds = test.cmdScript.split('\n');
            }
            args.push('-c', test.cmds.join(';'));
          }
          // append testfile
          args.push(binPath(test.file));

          let res = '';
          let ree = '';
          test.spawnArgs = args;
          const child = spawn(r2bin, args);
          test.birth = new Date();
          child.stdout.on('data', data => {
            res += data.toString();
          });
          child.stderr.on('data', data => {
            ree += data.toString();
          });
          child.on('close', data => {
            test.death = new Date();
            try {
              if (test.tmpScript) {
                // TODO use yield
                fs.unlinkSync(test.tmpScript);
                test.tmpScript = null;
              }
            } catch (e) {
              console.error(e);
              // ignore
            }
            test.lifetime = test.death - test.birth;
            test.stdout = res;
            test.stderr = ree;
            resolve(cb(test));
          });
        } catch (e) {
          console.error(e);
          reject(e);
        }
/*
        // using r2pipe, maybe viable for some tests
        let res = '';
        let r2 = null;
        try {
          const testPath = binPath(test.file);
          r2 = yield r2promise.open(testPath);
          for (let cmd in test.cmds) {
            res += yield r2.cmd(cmd);
          }
          if (r2 !== null) {
            yield r2.quit();
          }
          if (res.expect === res) {
            console.log('OK', test.name);
          } else {
            console.log('XX', test.name);
          }
          resolve(res);
        } catch (err) {
          console.error(err);
          process.exit(1);
          if (r2 !== null) {
            yield r2.quit();
          }
          return reject(err);
        }
*/
      });
    });
  }

  runTests (source, lines) {
    let test = {from: source};
    const editMode = {
      match: false,
      name: '',
      enabled: false,
      str: ''
    };
    // edit is work in progress. aka not working at all
    if (this.argv.e) {
      editMode.match = true;
      editMode.name = 'cmd_graph';
      process.exit(1);
    }
    const delims = /['"%]/;
    const stateEnum = Object.freeze({NORMAL: 0, CMDS_CONT: 1, EXPECT_CONT: 2});
    var state = stateEnum.NORMAL;
    var delim;
    var endDelim;
    for (let l of lines) {
      switch (state) {
        case stateEnum.CMDS_CONT:
          endDelim = l.indexOf(delim);
          if (endDelim == -1) {
            test.cmdScript += l + "\n";
          } else {
            test.cmdScript += l.substring(0, endDelim);
            test.cmds = test.cmdScript.trim().split('\n');
            state = stateEnum.NORMAL;
          }
          continue;
        case stateEnum.EXPECT_CONT:
          endDelim = l.indexOf(delim);
          if (endDelim == -1) {
            test.expect += l + "\n";
          } else {
            test.expect += l.substring(0, endDelim);
            state = stateEnum.NORMAL;
          }
          continue;
      }
      const line = l.trim();
      if (line.length === 0 || line[0] === '#') {
        continue;
      }
      if (editMode.enabled) {
        if (editMode.match) {
          console.log(line);
        }
        if (line === 'RUN') {
          editMode.match = false;
        }
        continue;
      }
      if (source.indexOf('asm') !== -1) {
        let tests = parseTestAsm(source, line);
        for (let t of tests) {
          this.promises.push(this.runTestAsm.bind(this)(t, this.checkTestResult.bind(this)));
        }
        continue;
      }
      if (line === 'RUN') {
        const testCallback = this.callbackFromPath(test.from);
        if (testCallback !== null) {
          this.promises.push(testCallback.bind(this)(test, this.checkTestResult.bind(this)));
          test = {from: source};
          continue;
        }
      }
      const eq = l.indexOf('=');
      if (eq === -1) {
        throw new Error('Invalid database', l);
      }
      const k = l.substring(0, eq);
      const v = l.substring(eq + 1);
      switch (k) {
        case 'NAME':
          test.name = v;
          if (editMode.enabled && editMode.name === v) {
            editMode.match = true;
          }
          break;
        case 'PATH':
          test.path = v;
          break;
        case 'ARGS':
          test.args = v || [];
          break;
        case 'CMDS':
          delim = v.trim().charAt(0);
          if (delims.test(delim)) {
            const startDelim = v.indexOf(delim);
            const endDelim = v.indexOf(delim, startDelim + 1);
            if (endDelim == -1) {
              test.cmdScript = v.substring(startDelim + 1) + "\n";
              state = stateEnum.CMDS_CONT;
              break;
            } else {
              test.cmdScript = v.substring(startDelim + 1, endDelim) + "\n";
            }
          } else {
            test.cmdScript = v ? v + "\n" : v;
          }
          test.cmds = test.cmdScript ? test.cmdScript.trim().split('\n') : [];
          break;
        case 'CMDS64':
          test.cmdScript = debase64(v);
          test.cmds = test.cmdScript ? test.cmdScript.trim().split('\n') : [];
          break;
        case 'ARCH':
          test.arch = v;
          break;
        case 'BITS':
          test.bits = v;
          break;
        case 'BROKEN':
          test.broken = true;
          break;
        case 'EXPECT':
          test.expect64 = false;
          delim = v.trim().charAt(0);
          if (delims.test(delim)) {
            test.expectDelim = delim;
            const startDelim = v.indexOf(delim);
            const endDelim = v.indexOf(delim, startDelim + 1);
            if (endDelim == -1) {
              test.expect = v.substring(startDelim + 1) + "\n";
              state = stateEnum.EXPECT_CONT;
              break;
            } else {
              test.expect = v.substring(startDelim + 1, endDelim) + "\n";
            }
          } else {
            test.expect = v + "\n";
          }
          break;
        case 'EXPECT64':
          test.expect = debase64(v);
          test.expect64 = true;
          break;
        case 'EXPECT_ERR':
          test.expect = v;
          break;
        case 'EXPECT_ERR64':
          test.expect = debase64(v);
          break;
        case 'FILE':
          test.file = v;
          break;
        default:
          throw new Error('Invalid database, key =(', k, ')');
      }
    }
    if (state !== stateEnum.NORMAL) {
      throw new Error('Unexpected EOF, state = ' + state);
    }
    if (Object.keys(test) !== 0) {
      if (test.file && test.cmds) {
        this.promises.push(this.runTest(test));
      }
    }
  }

  runFuzz (dir, files) {
    let test = {};
    for (let f of files) {
      test = {from: dir, name: 'fuzz', path: path.join(dir, f)};
      this.promises.push(this.runTestFuzz.bind(this)(test, this.checkTestResult.bind(this)));
    }
  }

  load (fileName, cb) {
    this.name = fileName;
    const blob = fs.readFileSync(path.join(__dirname, fileName));
    zlib.gunzip(blob, (err, data) => {
      if (err) {
        this.runTests(fileName, blob.toString().split('\n'));
      } else {
        this.runTests(fileName, data.toString().split('\n'));
      }
      Promise.all(this.promises).then(res => {
        this.printReport();
        cb(null, res);
      }).catch(err => {
        console.log(err);
        cb(err);
      });
    });
  }

  loadFuzz (dir, cb) {
    console.log('[--]', 'fuzz binaries');
    const fuzzed = fs.readdirSync(dir);
    this.runFuzz(dir, fuzzed);
    Promise.all(this.promises).then(res => {
      this.printReport();
      cb(null, res);
    }).catch(err => {
      console.log(err);
      cb(err);
    });
  }

  checkTest (test) {
    test.passes = test.expectErr ? test.expectErr.trim() === test.stderr.trim() : true;
    if (test.passes && typeof test.stdout !== 'undefined') { // && test.expect) {
      if (process.platform === 'win32') {
        /* Delete \r on windows.
         * Note that process.platform is always win32 even on Windows 64 bits */
        test.stdout = test.stdout.replace(/\r/g, '');
      }
      test.passes = test.expect64 || test.expect64 === undefined ? test.expect.trim() === test.stdout.trim() : test.expect === test.stdout;
    }
    const status = (test.passes)
    ? (test.broken ? colors.yellow('[FX]') : colors.green('[OK]'))
    : (test.broken ? colors.blue('[BR]') : colors.red('[XX]'));
    this.report.total++;
    if (test.passes) {
      if (test.broken) {
        this.report.fixed++;
      } else {
        this.report.success++;
      }
    } else {
      if (test.broken) {
        this.report.broken++;
      } else {
        this.report.failed++;
      }
    }
    /* Hack to hide undefined */
    if (test.path === undefined) {
      test.path = '';
    }
    if (test.lifetime === undefined) {
      test.lifetime = '';
    }
    if ((process.env.NOOK && status !== colors.green('[OK]')) || !process.env.NOOK) {
      // console.log('[' + status + ']', colors.yellow(test.name), test.path, test.lifetime);
      process.stdout.write('\x1b[0K\r' + status + ' ' + test.from + ' ' + colors.yellow(test.name) + ' ' + test.path  + ' ' + test.lifetime + (this.verbose ? '\n' : '\r'));
    }
    return test.passes;
  }

  checkTestResult (test) {
    const testHasFailed = !this.checkTest(test);
    if (this.interactive) {
      this.verbose = true;
    }
    if (!this.verbose && (test.broken || test.fixed)) {
      return;
    }
    /* Do not show diff if TRAVIS or APPVEYOR and if test is broken */
    if ((process.env.TRAVIS || process.env.APPVEYOR) && test.broken) {
      return;
    }
    if (testHasFailed) {
      console.log('\n$ r2', test.spawnArgs ? test.spawnArgs.join(' ') : '');
      if (test.cmdScript !== undefined) {
        console.log(test.cmdScript);
      }

      const changes = jsdiff.diffLines(test.expect, test.stdout);
      changes.forEach(function (part) {
        const k = part.added ? colors.green : colors.magenta;
        const v = part.value.replace(/[\r\n]*$/, '');
        if (part.added) {
          common.highlightTrailingWs(k, '+' + v.split(/\n/g).join('\n+') + '\n');
        } else if (part.removed) {
          common.highlightTrailingWs(k, '-' + v.split(/\n/g).join('\n-') + '\n');
        } else {
          common.highlightTrailingWs(null, ' ' + v.split(/\n/g).join('\n ') + '\n');
        }
      });
/*
      console.log('===');
      if (test.expect !== null) {
        ///console.log('---');
        console.log(colors.magenta(test.expect.trim()));
      }
      if (test.stdout !== null) {
        // console.log('+++');
        console.log(colors.green(test.stdout.trim()));
      }
*/
      // console.log('===');
      if (test.expect64) {
        console.log('EXPECT64=' + base64(test.stdout));
      } else if (test.expect64 !== undefined) {
        if (test.expectDelim === undefined) {
          test.expectDelim = '%';
        }
        common.highlightTrailingWs(null, '\nEXPECT=' + test.expectDelim + test.stdout + test.expectDelim + '\n',
                                   false);
      }
      if (this.interactive) {
//        console.log('TODO: interactive thing should happen here');
      }
      this.queue.push(test);
    }
  }

  printReport () {
    this.report.totaltime = new Date() - this.start;
    const r = {
      name: this.name,
      OK: this.report.success,
      BR: this.report.broken,
      XX: this.report.failed,
      FX: this.report.fixed,
      time: this.report.totaltime
    };
    function n (x) {
      return x.toString().padStart(4);
    }
    const name = (typeof this.name === 'string') ? this.name.padStart(30) : '';
    console.log('[**]', name + '  ', 'OK', n(r.OK), 'BR', n(r.BR), 'XX', n(r.XX), 'FX', n(r.FX));
  }

  fixTest (name, expect, cb) {
  }

  editTest (name, expect, cb) {
  }
}

function createTemporaryFile () {
  return new Promise((resolve, reject) => {
    try {
      tmp.file(function (err, filePath, fd, cleanupCallback) {
        if (err) {
          return reject(err);
        }
        resolve(filePath);
      });
    } catch (e) {
      reject(e);
    }
  });
}

function parseTestAsm (source, line) {
  /* Parse first argument */
  let r2args = [];
  let args = line.match(/(".*?"|[^"\s]+)+(?=\s*|\s*$)/g);
  if (args.length < 3) {
    console.error(colors.red.bold('[XX]', 'Wrong test format in ' + source + ':' + line));
    return [];
  }
  let filetree = source.split(path.sep);
  const filename = filetree[filetree.length - 1].split('_');
  if (filename.length > 3) {
    console.error(colors.red.bold('[XX]', 'Wrong filename: ' + source));
    return [];
  } else if (filename.length === 2) {
    r2args.push('e asm.bits=' + filename[1]);
  } else if (filename.length === 3) {
    r2args.push('e asm.cpu=' + filename[1]);
    r2args.push('e asm.bits=' + filename[2]);
  }
  r2args.push('e asm.arch=' + filename[0]);

  let type = args[0];
  let asm = args[1].split('"').join('');
  let expect = args[2];
  if (args.length >= 4) {
    r2args.push('s ' + args[3]);
  } else {
    r2args.push('s 0');
  }

  /* Generate tests */
  let tests = [];
  for (let c of type) {
    let t = {from: source, broken: false, args: r2args.join(';')};
    t.endianess = false
    if (type.indexOf('E') !== -1) {
      t.endianess = true;
    }
    switch (c) {
      case 'd':
        t.cmd = "e cfg.bigendian=" + t.endianess + ";" + 'pad ' + expect;
        t.expect = asm;
        t.name = filename + ': ' + expect + ' => "' + asm + '"' + colors.blue(' (disassemble)');
        tests.push(t);
        break;
      case 'a':
        t.cmd = "e cfg.bigendian=" + t.endianess + ";" + 'pa ' + asm;
        t.expect = expect;
        t.name = filename + ': "' + asm + '" => ' + expect + colors.blue(' (assemble)');
        tests.push(t);
        break;
      default:
        continue;
    }
    if (type.indexOf('B') !== -1) {
      t.broken = true;
    }
  }
  return tests;
}

function debase64 (msg) {
  return Buffer.from(msg, 'base64').toString('utf8');
}

function base64 (msg) {
  return Buffer.from(msg).toString('base64');
}

function binPath (file) {
  if (file && file[0] === '.') {
    return path.join(__dirname, file);
  }
  return file;
}

module.exports = NewRegressions;
