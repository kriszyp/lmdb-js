/**
 * resize.js 0.3 970811
 * by gary smith
 * js component for "reloading page onResize"
 */

if(!window.saveInnerWidth) {
  window.onresize = resize;
  window.saveInnerWidth = window.innerWidth;
  window.saveInnerHeight = window.innerHeight;
}

function resize() {
    if (saveInnerWidth < window.innerWidth || 
        saveInnerWidth > window.innerWidth || 
        saveInnerHeight > window.innerHeight || 
        saveInnerHeight < window.innerHeight ) 
    {
        window.history.go(0);
    }
}
