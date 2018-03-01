const colors = require('colors/safe');

module.exports = {
  identity (arg) {
    return arg;
  },
  highlightTrailingWs (colorFunc, text, diff = true) {
    wsColorFunc = colors.bgRed;
    if (colorFunc == null) {
      colorFunc = this.identity;
      if (diff) {
        wsColorFunc = this.identity;
      }
    }
    const wsTrailing = /[ \t]+$/gm;
    var curIndex = 0;
    var match;
    while ((match = wsTrailing.exec(text)) !== null) {
      process.stdout.write(colorFunc(text.substring(curIndex, wsTrailing.lastIndex - match[0].length))
                           + wsColorFunc(match[0]));
      curIndex = wsTrailing.lastIndex;
    }
    process.stdout.write(colorFunc(text.substring(curIndex)));
  }
};
