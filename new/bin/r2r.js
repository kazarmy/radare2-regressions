#!/usr/bin/env node

const NewRegressions = require('..');
const fs = require('fs');
const jsdiff = require('diff');
const colors = require('colors/safe');
const spawnSync = require('child_process').spawnSync;
const minimist = require('minimist');
const walk = require('walk').walk;
const path = require('path');
const readline = require('readline');
const common = require('../common');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
rl.on('line', line => {
  // rl.close();
  if (rl.cb) {
    rl.cb(null, line.trim());
  }
});
rl.on('error', err => {
  if (rl.cb) {
    rl.cb(err);
    rl.cb = null;
  }
});

const flagMap = {
  '-h': '--help',
  '-g': '--grep',
  '-i': '--interactive',
  '-l': '--list',
  '-v': '--verbose'
};
const args = process.argv.slice(2).map(_ => {
  return flagMap[_] || _;
});
const delims = /['"%]/;

main(minimist(args, {
  boolean: ['v', 'verbose', 'i', 'interactive', 'l', 'list', 'format'],
  string: ['g', 'grep']
}));

function main (argv) {
  if (argv.help) {
    console.log(`Usage: r2r [options] [filter]
 -a    add new test
 -b    mark failing tests as broken
 -c    use -c instead of -i to run r2 (EXPERIMENTAL)
 -d    delete test
 -e    edit test
 -f    fix tests that are not passing
 -g    grep
 -i    interactive mode
 -j    output in JSON
 -l    list all tests
 -u    unmark broken in fixed tests
 -v    be verbose (show broken tests and use more newlines)
 --format
       format tests (i.e. add blank lines between tests)`);
    rl.close();
    return 0;
  }

  const nr = new NewRegressions(argv, function ready (err, res) {
    if (err) {
      return 1;
    }
    if (argv.g) {
      console.error('TODO: grep');
      nr.quit();
      return 0;
    }
    if (argv.l) {
      console.error('TODO: list');
      nr.quit();
      return 0;
    }
    if (argv.e) {
      console.error('TODO');
      nr.quit();
      return 0;
    }
    if (argv.a) {
      console.error('TODO: Use: r2r -a instead of r2r.js for now');

      const test = {
        from: argv.a,
        name: argv._[0],
        cmdScript: argv._[1],
        file: argv._[2] || 'malloc://128' // maybe -- ?
      };
      nr.runTest(test, (res) => {
        delete res.spawnArgs;
        // TODO: include this into the given test
        console.log(JSON.stringify(res, null, '  '));
      }).then(res => {
        // console.log('RESULT', res);
      }).catch(err => {
        console.error(err);
      });

      nr.quit();
      return 0;
    }

    // Load tests
    let watdo = 0;
    const walker = walk('db', {followLinks: false});
    const filter = argv._[0] || '';
    walker.on('file', (root, stat, next) => {
      const testFile = path.join(root, stat.name);
      if (testFile.indexOf(filter) === -1) {
        return next();
      }
      // console.log('[--]', 'run', testFile);
      if (testFile.indexOf('/.') !== -1) {
      // skip hidden files
        return next();
      }
      nr.load(testFile, (err, data) => {
        if (err) {
          console.log('[XX] WAT DO', testFile);
          console.error(err.message);
          watdo++;
        }
        next();
      });
    });
    walker.on('end', () => {
      if (watdo > 0) {
        // XXX this is probably wrong
        process.exit(1);
      }
      if (!filter || filter === 'fuzz') {
        // Load fuzzed binaries
        nr.loadFuzz('../bins/fuzzed', (err, data) => {
          if (err) {
            console.error(err.message);
          }
        });
      }
      function readLine (cb) {
        rl.cb = cb;
        rl.prompt();
      }
      function fin (err) {
        if (err) {
          console.error(err);
        }
        const code = process.env.APPVEYOR ? 0 : nr.report.failed > 0;
        process.exit(code);
      }
      function pullQueue (cb) {
        if (nr.queue.length === 0) {
          return cb();
        }
        const test = nr.queue.pop();
        if (test.broken) {
          return next();
        }
        function next () {
          setTimeout(_ => { pullQueue(cb); }, 0);
        }
        console.log('This test has failed:');
        console.log('File:', test.file);
        console.log('Script:', test.from);
        console.log('Name:', test.name);
        //  console.log('-', test.expect);
        // console.log('+', test.stdout);

        try {
          verifyTest(test);
        } catch (e) {
          return cb(e);
        }

        console.log('Input:', test.cmds);

        let showHeaders = test.stderrFail;
        if (test.stdoutFail) {
          if (showHeaders) {
            console.log('Stream: stdout\n');
          }
          common.showDiff(test.expect, test.stdout);
        }
        if (test.stdoutFail && test.stderrFail) {
          console.log();
        }
        if (test.stderrFail) {
          if (showHeaders) {
            console.log('Stream: stderr\n');
          }
          common.showDiff(test.expectErr, test.stderr);
        }

        console.log('Wat du? (f)ix (i)gnore (b)roken (q)uit (c)ommands (d)iffChars');
        readLine(function handleKey (err, line) {
          if (err) {
            return cb(err);
          }
          rl.cb = null;
          switch (line) {
            case 'q':
              console.error('Aborted');
              process.exit(1);
            // unreachable break;
            case 'i':
              next();
              break;
            case 'b':
              markAsBroken(test, next);
              break;
            case 'f':
              fixTest(test, next);
              break;
            case 'c':
              fixCommands(test, next);
              break;
            case 'd':
              let showHeaders = test.stdoutFail && test.stderrFail;
              if (test.stdoutFail) {
                if (showHeaders) {
                  console.log('Stream: stdout\n');
                }
                common.showDiffChars(test.expect, test.stdout);
              }
              if (test.stdoutFail && test.stderrFail) {
                console.log();
              }
              if (test.stderrFail) {
                if (showHeaders) {
                  console.log('Stream: stderr\n');
                }
                common.showDiffChars(test.expectErr, test.stderr);
              }
              console.log('Wat du? (f)ix (i)gnore (b)roken (q)uit (c)ommands');
              readLine(handleKey);
              break;
          }
        });
      }
      nr.quit().then(_ => {
        if (nr.queue.length > 0 && (argv.interactive || argv.i)) {
          console.error(nr.queue.length, 'failed tests');
          pullQueue(fin);
        } else {
          fin();
        }
      });
    });

    return 0;
  });
}

// TODO: move into a module
function markAsBroken (test, next) {
  const filePath = test.from;
  let output = '';
  // read all lines from filepath and stop when finding the test that matches
  try {
    let lines = fs.readFileSync(filePath).toString().trim().split('\n');
    for (let line of lines) {
      output += line + '\n';
      if (line.startsWith('NAME=')) {
        const name = line.substring(5);
        if (name === test.name) {
          console.error('TEST FOUND!!! BINGO :D');
          output += 'BROKEN=1\n';
        }
      }
    }
    fs.writeFileSync(filePath, output);
  } catch (err) {
    console.error(err);
  } finally {
    next();
  }
}

function fixTest (test, next) {
  const filePath = test.from;
  let output = '';
  // read all lines from filepath and stop when finding the test that matches
  try {
    let lines = fs.readFileSync(filePath).toString().trim().split('\n');
    let target = null;
    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];
      if (target) {
        if (line.startsWith('EXPECT64=')) {
          const msg = Buffer.from(test.stdout).toString('base64');
          output += 'EXPECT64=' + msg + '\n';
        } else if (line.startsWith('EXPECT=')) {
          const val = line.substring(7);
          const valTrim = val.trim();
          if (valTrim.startsWith('<<')) {
            const endString = valTrim.substring(2);
            i++;
            while (!lines[i].startsWith(endString)) {
              i++;
            }
            i--;
            output += 'EXPECT=<<' + endString + '\n' + test.stdout;
          } else {
            let delim = valTrim.charAt(0);
            if (delims.test(delim)) {
              const startDelim = val.indexOf(delim);
              const endDelim = val.indexOf(delim, startDelim + 1);
              if (endDelim === -1) {
                i++;
                while (lines[i].indexOf(delim) === -1) {
                  i++;
                }
              }
            } else {
              delim = '%';
            }
            output += 'EXPECT=' + delim + test.stdout + delim + '\n';
          }
        } else if (line.startsWith('EXPECT_ERR=')) {
          if ((test.stderr.match(/\n/g) || []).length > 1) {
            const val = line.substring(11);
            const valTrim = val.trim();
            if (valTrim.startsWith('<<')) {
              const endString = valTrim.substring(2);
              i++;
              while (!lines[i].startsWith(endString)) {
                i++;
              }
              i--;
              output += 'EXPECT_ERR=<<' + endString + '\n' + test.stderr;
            } else {
              let delim = valTrim.charAt(0);
              if (delims.test(delim)) {
                const startDelim = val.indexOf(delim);
                const endDelim = val.indexOf(delim, startDelim + 1);
                if (endDelim === -1) {
                  i++;
                  while (lines[i].indexOf(delim) === -1) {
                    i++;
                  }
                }
              } else {
                delim = '%';
              }
              output += 'EXPECT_ERR=' + delim + test.stderr + delim + '\n';
            }
          } else {
            output += 'EXPECT_ERR=' + test.stderr;
          }
        } else {
          output += line + '\n';
        }
      } else {
        output += line + '\n';
      }
      if (line.startsWith('RUN')) {
        target = null;
      }
      if (line.startsWith('NAME=')) {
        const name = line.substring(5);
        if (name === test.name) {
          target = name;
        }
      }
    }
    fs.writeFileSync(filePath, output);
    next();
  } catch (err) {
    console.error(err);
    next();
  }
}

function editFile (someFile) {
  const editor = process.env.EDITOR || 'vi';
  spawnSync(editor, [someFile], { stdio: 'inherit' });
}

function editCmds (cmds) {
  fs.writeFileSync('.cmds.txt', cmds);
  editFile('.cmds.txt');
  return fs.readFileSync('.cmds.txt').toString();
}

function fixCommands (test, next) {
  const filePath = test.from;
  let output = '';
  // read all lines from filepath and stop when finding the test that matches
  try {
    let lines = fs.readFileSync(filePath).toString().trim().split('\n');
    let target = null;
    let msg;
    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];
      if (target) {
        if (line.startsWith('CMDS64=')) {
          msg = Buffer.from(line.substring(7), 'base64');
          fs.writeFileSync('.cmds.txt', msg);
          editFile('.cmds.txt');
          const cmds = fs.readFileSync('.cmds.txt').toString('base64');
          output += 'CMDS64=' + cmds + '\n';
        } else if (line.startsWith('CMDS=')) {
          const val = line.substring(5);
          const valTrim = val.trim();
          if (valTrim.startsWith('<<')) {
            const endString = valTrim.substring(2);
            msg = '';
            i++;
            while (!lines[i].startsWith(endString)) {
              msg += lines[i] + '\n';
              i++;
            }
            i--;
            const cmds = editCmds(msg);
            output += 'CMDS=<<' + endString + '\n' + cmds;
          } else {
            let delim = valTrim.charAt(0);
            if (delims.test(delim)) {
              const startDelim = val.indexOf(delim);
              let endDelim = val.indexOf(delim, startDelim + 1);
              if (endDelim == -1) {
                msg = val.substring(startDelim + 1) + '\n';
                i++;
                while ((endDelim = lines[i].indexOf(delim)) == -1) {
                  msg += lines[i] + '\n';
                  i++;
                }
                msg += lines[i].substring(0, endDelim);
              } else {
                msg = val.substring(startDelim + 1, endDelim) + '\n';
              }
            } else {
              msg = val;
            }
            const cmds = editCmds(msg);
            if (!delims.test(delim)) {
              delim = '%';
            }
            output += 'CMDS=' + delim + cmds + delim + '\n';
          }
        } else {
          output += line + '\n';
        }
      } else {
        output += line + '\n';
      }
      if (line.startsWith('RUN')) {
        target = null;
      }
      if (line.startsWith('NAME=')) {
        // TODO: ensure expect is valid
        const name = line.substring(5);
        if (name === test.name) {
          target = name;
        }
      }
    }
    fs.writeFileSync(filePath, output);
    next();
  } catch (err) {
    console.error(err);
    next();
  }
}

const tests = [];
function verifyTest (test) {
  if (tests.indexOf(test.name) !== -1) {
    throw new Error('Found two tests with the same name', JSON.stringify(test, null, 2));
  }
  tests.push(test.name);
}
