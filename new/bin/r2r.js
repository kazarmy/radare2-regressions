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
  '-v': '--verbose'
};
const args = process.argv.slice(2).map(_ => {
  return flagMap[_] || _;
});
const delims = /['"%]/;

main(minimist(args, {
  boolean: ['v', 'verbose', 'i', 'interactive']
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
 -v    be verbose (show broken tests and use more newlines)`);
    rl.close()
    return 0;
  }

  const nr = new NewRegressions(argv, function ready (err, res) {
    if (err) {
      return 1;
    }

    if (argv.e) {
      console.error('TODO');
      nr.quit();
      return 0;
    }
    if (argv.a) {
      console.error('TODO: Use: r2r -a instead of r2r.js for now');
/*
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
*/
      nr.quit();
      return 0;
    }

    // Load tests
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
          console.error(err.message);
          console.log('WAT DO');
        }
        next();
      });
    });
    walker.on('end', () => {
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
        const changes = jsdiff.diffLines(test.expect, test.stdout);
        changes.forEach(function (part) {
          const k = part.added ? colors.green : colors.magenta;
          const v = part.value.replace(/[\r\n]*$/, '');
          if (part.added) {
            common.highlightTrailingWs(k, '+' + v.split(/\n/g).join('\n+') + '\n');
          } else if (part.removed) {
            common.highlightTrailingWs(k, '-' + v.split(/\n/g).join('\n-') + '\n');
          } else {
            console.log(' ' + v.split(/\n/g).join('\n '));
          }
        });

        console.log('Wat du? (f)ix (i)gnore (b)roken (q)uit (c)ommands (d)iffChars');
        readLine(function handleKey(err, line) {
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
              const changes = jsdiff.diffChars(test.expect, test.stdout);
              changes.forEach(function (part) {
                const k = part.added ? colors.black.bgGreen :
                                       colors.white.bold.bgMagenta.strikethrough;
                const v = part.value;
                if (part.added || part.removed) {
                  process.stdout.write(k(v));
                } else {
                  process.stdout.write(colors.grey(v));
                }
              });
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
    next();
  } catch (err) {
    console.error(err);
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
    const stateEnum = Object.freeze({NORMAL: 0, EXPECT_CONT: 1});
    let state = stateEnum.NORMAL;
    let delim = null;
    let endString = null;
    for (let line of lines) {
      if (target) {
        if (state === stateEnum.EXPECT_CONT) {
          if (delim !== null) {
            const endDelim = line.indexOf(delim);
            if (endDelim !== -1) {
              output += 'EXPECT=' + delim + test.stdout + delim + '\n';
              state = stateEnum.NORMAL;
            }
            continue;
          } else if (endString !== null) {
            if (line.startsWith(endString)) {
              output += 'EXPECT=<<' + endString + '\n' + test.stdout;
              state = stateEnum.NORMAL;
              // no continue
            } else {
              continue;
            }
          } else {
            throw new Error('Internal error, EXPECT_CONT');
          }
        }
        if (line.startsWith('EXPECT64=')) {
          const msg = Buffer.from(test.stdout).toString('base64');
          output += 'EXPECT64=' + msg + '\n';
        } else if (line.startsWith('EXPECT=')) {
          delim = null;
          endString = null;
          const val = line.substring(7);
          const valTrim = val.trim();
          if (valTrim.startsWith('<<')) {
            endString = valTrim.substring(2);
            state = stateEnum.EXPECT_CONT;
            continue;
          }
          delim = valTrim.charAt(0);
          if (delims.test(delim)) {
            const startDelim = val.indexOf(delim);
            const endDelim = val.indexOf(delim, startDelim + 1);
            if (endDelim === -1) {
              state = stateEnum.EXPECT_CONT;
              continue;
            }
          } else {
            delim = '%';
          }
          output += 'EXPECT=' + delim + test.stdout + delim + '\n';
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

function fixCommands (test, next) {
  const filePath = test.from;
  let output = '';
  // read all lines from filepath and stop when finding the test that matches
  try {
    let lines = fs.readFileSync(filePath).toString().trim().split('\n');
    let target = null;
    let msg;
    const stateEnum = Object.freeze({NORMAL: 0, CMDS_CONT: 1});
    let state = stateEnum.NORMAL;
    let delim = null;
    let endString = null;
    for (let line of lines) {
      if (target) {
        if (state === stateEnum.CMDS_CONT) {
          if (delim !== null) {
            const endDelim = line.indexOf(delim);
            if (endDelim == -1) {
              msg += line + '\n';
            } else {
              msg += line.substring(0, endDelim);
              fs.writeFileSync('.cmds.txt', msg);
              editFile('.cmds.txt');
              const cmds = fs.readFileSync('.cmds.txt').toString();
              output += 'CMDS=' + delim + cmds + delim + '\n';
              state = stateEnum.NORMAL;
            }
            continue;
          } else if (endString !== null) {
            if (line.startsWith(endString)) {
              fs.writeFileSync('.cmds.txt', msg);
              editFile('.cmds.txt');
              const cmds = fs.readFileSync('.cmds.txt').toString();
              output += 'CMDS=<<' + endString + '\n' + cmds;
              state = stateEnum.NORMAL;
              // no continue
            } else {
              msg += line + '\n';
              continue;
            }
          } else {
            throw new Error('Internal error, CMDS_CONT');
          }
        }
        if (line.startsWith('CMDS64=')) {
          msg = Buffer.from(line.substring(7), 'base64');
          fs.writeFileSync('.cmds.txt', msg);
          editFile('.cmds.txt');
          const cmds = fs.readFileSync('.cmds.txt').toString('base64');
          output += 'CMDS64=' + cmds + '\n';
        } else if (line.startsWith('CMDS=')) {
          delim = null;
          endString = null;
          const val = line.substring(5);
          const valTrim = val.trim();
          if (valTrim.startsWith('<<')) {
            endString = valTrim.substring(2);
            msg = '';
            state = stateEnum.CMDS_CONT;
            continue;
          }
          delim = valTrim.charAt(0);
          if (delims.test(delim)) {
            const startDelim = val.indexOf(delim);
            const endDelim = val.indexOf(delim, startDelim + 1);
            if (endDelim == -1) {
              msg = val.substring(startDelim + 1) + '\n';
              state = stateEnum.CMDS_CONT;
              continue;
            } else {
              msg = val.substring(startDelim + 1, endDelim) + '\n';
            }
          } else {
            msg = val;
          }
          fs.writeFileSync('.cmds.txt', msg);
          editFile('.cmds.txt');
          const cmds = fs.readFileSync('.cmds.txt').toString();
          if (!delims.test(delim)) {
            delim = '%';
          }
          output += 'CMDS=' + delim + cmds + delim + '\n';
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
function verifyTest(test) {
  if (tests.indexOf(test.name) !== -1) {
    throw new Error('Found two tests with the same name', JSON.stringify(test, null, 2));
  }
  tests.push(test.name);
}
