(function(){
var de=document.documentElement;
function has(el,c){return(' '+el.className+' ').indexOf(' '+c+' ')>-1}
function add(el,c){if(!has(el,c))el.className+=' '+c}
function rem(el,c){el.className=(' '+el.className+' ').replace(' '+c+' ',' ').replace(/^\s+|\s+$/g,'')}
/* keyboard-only focus ring (works without :focus-visible) */
document.addEventListener('keydown',function(e){if(e.key==='Tab'||e.keyCode===9)add(de,'wd-kb')},true);
document.addEventListener('mousedown',function(){rem(de,'wd-kb')},true);
/* loading helper for any .wd-btn */
window.wdBtnBusy=function(el,on){
 if(!el)return;
 if(on&&!has(el,'wd-loading')){add(el,'wd-loading');el.setAttribute('aria-busy','true')}
 else if(!on&&has(el,'wd-loading')){rem(el,'wd-loading');el.removeAttribute('aria-busy')}
};
})();
