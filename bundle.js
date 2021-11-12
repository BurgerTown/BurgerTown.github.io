"use strict";var sendPageView,_excluded=["id","async","defer","crossOrigin","dataset"];function _slicedToArray(e,t){return _arrayWithHoles(e)||_iterableToArrayLimit(e,t)||_unsupportedIterableToArray(e,t)||_nonIterableRest()}function _nonIterableRest(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}function _iterableToArrayLimit(e,t){var n=null==e?null:"undefined"!=typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=n){var o,r,a=[],i=!0,c=!1;try{for(n=n.call(e);!(i=(o=n.next()).done)&&(a.push(o.value),!t||a.length!==t);i=!0);}catch(e){c=!0,r=e}finally{try{i||null==n.return||n.return()}finally{if(c)throw r}}return a}}function _arrayWithHoles(e){if(Array.isArray(e))return e}function _objectWithoutProperties(e,t){if(null==e)return{};var n,o=_objectWithoutPropertiesLoose(e,t);if(Object.getOwnPropertySymbols)for(var r=Object.getOwnPropertySymbols(e),a=0;a<r.length;a++)n=r[a],0<=t.indexOf(n)||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n]);return o}function _objectWithoutPropertiesLoose(e,t){if(null==e)return{};for(var n,o={},r=Object.keys(e),a=0;a<r.length;a++)n=r[a],0<=t.indexOf(n)||(o[n]=e[n]);return o}function _toConsumableArray(e){return _arrayWithoutHoles(e)||_iterableToArray(e)||_unsupportedIterableToArray(e)||_nonIterableSpread()}function _nonIterableSpread(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}function _unsupportedIterableToArray(e,t){if(e){if("string"==typeof e)return _arrayLikeToArray(e,t);var n=Object.prototype.toString.call(e).slice(8,-1);return"Map"===(n="Object"===n&&e.constructor?e.constructor.name:n)||"Set"===n?Array.from(e):"Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)?_arrayLikeToArray(e,t):void 0}}function _iterableToArray(e){if("undefined"!=typeof Symbol&&null!=e[Symbol.iterator]||null!=e["@@iterator"])return Array.from(e)}function _arrayWithoutHoles(e){if(Array.isArray(e))return _arrayLikeToArray(e)}function _arrayLikeToArray(e,t){(null==t||t>e.length)&&(t=e.length);for(var n=0,o=new Array(t);n<t;n++)o[n]=e[n];return o}function ownKeys(t,e){var n,o=Object.keys(t);return Object.getOwnPropertySymbols&&(n=Object.getOwnPropertySymbols(t),e&&(n=n.filter(function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})),o.push.apply(o,n)),o}function _objectSpread(t){for(var e=1;e<arguments.length;e++){var n=null!=arguments[e]?arguments[e]:{};e%2?ownKeys(Object(n),!0).forEach(function(e){_defineProperty(t,e,n[e])}):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(n)):ownKeys(Object(n)).forEach(function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(n,e))})}return t}function _defineProperty(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function _typeof(e){return(_typeof="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}window.NexT||(window.NexT={}),function(){function r(e){var t=document.querySelector(".".concat("next-config",'[data-name="').concat(e,'"]'));t&&(t=t.text,t=JSON.parse(t||"{}"),"main"===e?Object.assign(a,t):i[e]=t)}var a={},i={};r("main"),window.CONFIG=new Proxy({},{get:function(e,t){var n=t in a?a[t]:(t in i||r(t),i[t]);if(t in e||"object"!==_typeof(n)||(e[t]={}),t in e){var o=e[t];return"object"===_typeof(o)&&"object"===_typeof(n)?new Proxy(_objectSpread(_objectSpread({},n),o),{set:function(e,t,n){return e[t]=n,o[t]=n,!0}}):o}return n}}),document.addEventListener("pjax:success",function(){i={}})}(),CONFIG.google_analytics.only_pageview?(sendPageView=function(){var e;CONFIG.hostname===location.hostname&&(e=localStorage.getItem("uid")||Math.random()+"."+Math.random(),localStorage.setItem("uid",e),navigator.sendBeacon("https://www.google-analytics.com/collect",new URLSearchParams({v:1,tid:CONFIG.google_analytics.tracking_id,cid:e,t:"pageview",dp:encodeURIComponent(location.pathname)})))},document.addEventListener("pjax:complete",sendPageView),sendPageView()):CONFIG.hostname===location.hostname&&(window.dataLayer=window.dataLayer||[],window.gtag=function(){dataLayer.push(arguments)},gtag("js",new Date),gtag("config",CONFIG.google_analytics.tracking_id),document.addEventListener("pjax:success",function(){gtag("event","page_view",{page_location:location.href,page_path:location.pathname,page_title:document.title})})),window.addEventListener("tabs:register",function(){var e=CONFIG.comments.activeClass;!(e=CONFIG.comments.storage?localStorage.getItem("comments_active")||e:e)||(e=document.querySelector('a[href="#comment-'.concat(e,'"]')))&&e.click()}),CONFIG.comments.storage&&window.addEventListener("tabs:click",function(e){e.target.matches(".tabs-comment .tab-content .tab-pane")&&(e=e.target.classList[1],localStorage.setItem("comments_active",e))}),HTMLElement.prototype.wrap=function(e){this.parentNode.insertBefore(e,this),this.parentNode.removeChild(this),e.appendChild(this)},function(){function e(){return document.dispatchEvent(new Event("page:loaded",{bubbles:!0}))}"loading"===document.readyState?document.addEventListener("readystatechange",e,{once:!0}):e(),document.addEventListener("pjax:success",e)}(),NexT.utils={registerExtURL:function(){document.querySelectorAll("span.exturl").forEach(function(e){var t=document.createElement("a");t.href=decodeURIComponent(atob(e.dataset.url).split("").map(function(e){return"%"+("00"+e.charCodeAt(0).toString(16)).slice(-2)}).join("")),t.rel="noopener external nofollow noreferrer",t.target="_blank",t.className=e.className,t.title=e.title,t.innerHTML=e.innerHTML,e.parentNode.replaceChild(t,e)})},registerCopyCode:function(){var e=document.querySelectorAll("figure.highlight");(e=0===e.length?document.querySelectorAll("pre:not(.mermaid)"):e).forEach(function(n){var o;n.querySelectorAll(".code .line span").forEach(function(t){t.classList.forEach(function(e){t.classList.replace(e,"hljs-".concat(e))})}),CONFIG.copycode&&(n.insertAdjacentHTML("beforeend",'<div class="copy-btn"><i class="fa fa-copy fa-fw"></i></div>'),(o=n.querySelector(".copy-btn")).addEventListener("click",function(){var e,t=(n.querySelector(".code")||n.querySelector("code")).innerText;navigator.clipboard?navigator.clipboard.writeText(t).then(function(){o.querySelector("i").className="fa fa-check-circle fa-fw"},function(){o.querySelector("i").className="fa fa-times-circle fa-fw"}):((e=document.createElement("textarea")).style.top=window.scrollY+"px",e.style.position="absolute",e.style.opacity="0",e.readOnly=!0,e.value=t,document.body.append(e),e.select(),e.setSelectionRange(0,t.length),e.readOnly=!1,t=document.execCommand("copy"),o.querySelector("i").className=t?"fa fa-check-circle fa-fw":"fa fa-times-circle fa-fw",e.blur(),o.blur(),document.body.removeChild(e))}),n.addEventListener("mouseleave",function(){setTimeout(function(){o.querySelector("i").className="fa fa-copy fa-fw"},300)}))})},wrapTableWithBox:function(){document.querySelectorAll("table").forEach(function(e){var t=document.createElement("div");t.className="table-container",e.wrap(t)})},registerVideoIframe:function(){document.querySelectorAll("iframe").forEach(function(t){var e,n,o;["www.youtube.com","player.vimeo.com","player.youku.com","player.bilibili.com","www.tudou.com"].some(function(e){return t.src.includes(e)})&&!t.parentNode.matches(".video-container")&&((e=document.createElement("div")).className="video-container",t.wrap(e),n=Number(t.width),o=Number(t.height),n&&o&&(e.style.paddingTop=o/n*100+"%"))})},registerScrollPercent:function(){var t=this,n=document.querySelector(".back-to-top"),o=document.querySelector(".reading-progress-bar");window.addEventListener("scroll",function(){var e;(n||o)&&(e=0<(e=document.body.scrollHeight-window.innerHeight)?Math.min(100*window.scrollY/e,100):0,n&&(n.classList.toggle("back-to-top-on",5<=Math.round(e)),n.querySelector("span").innerText=Math.round(e)+"%"),o&&o.style.setProperty("--progress",e.toFixed(2)+"%")),Array.isArray(NexT.utils.sections)&&(-1===(e=NexT.utils.sections.findIndex(function(e){return e&&10<e.getBoundingClientRect().top}))?e=NexT.utils.sections.length-1:0<e&&e--,t.activateNavByIndex(e))},{passive:!0}),n&&n.addEventListener("click",function(){window.anime({targets:document.scrollingElement,duration:500,easing:"linear",scrollTop:0})})},registerTabsTag:function(){document.querySelectorAll(".tabs ul.nav-tabs .tab").forEach(function(n){n.addEventListener("click",function(e){var t;e.preventDefault(),n.classList.contains("active")||(_toConsumableArray((e=n.parentNode).children).forEach(function(e){e.classList.toggle("active",e===n)}),_toConsumableArray((t=document.getElementById(n.querySelector("a").getAttribute("href").replace("#",""))).parentNode.children).forEach(function(e){e.classList.toggle("active",e===t)}),t.dispatchEvent(new Event("tabs:click",{bubbles:!0})),CONFIG.stickytabs&&(e=e.parentNode.getBoundingClientRect().top+window.scrollY+10,window.anime({targets:document.scrollingElement,duration:500,easing:"linear",scrollTop:e})))})}),window.dispatchEvent(new Event("tabs:register"))},registerCanIUseTag:function(){window.addEventListener("message",function(e){var t=e.data;"string"==typeof t&&t.includes("ciu_embed")&&(e=t.split(":")[1],t=t.split(":")[2],document.querySelector("iframe[data-feature=".concat(e,"]")).style.height=parseInt(t,10)+5+"px")},!1)},registerActiveMenuItem:function(){document.querySelectorAll(".menu-item a[href]").forEach(function(e){var t=e.pathname===location.pathname||e.pathname===location.pathname.replace("index.html",""),n=!CONFIG.root.startsWith(e.pathname)&&location.pathname.startsWith(e.pathname);e.classList.toggle("menu-item-active",e.hostname===location.hostname&&(t||n))})},registerLangSelect:function(){document.querySelectorAll(".lang-select").forEach(function(e){e.value=CONFIG.page.lang,e.addEventListener("change",function(){var t=e.options[e.selectedIndex];document.querySelectorAll(".lang-select-label span").forEach(function(e){e.innerText=t.text}),window.location.href=t.dataset.href})})},registerSidebarTOC:function(){this.sections=_toConsumableArray(document.querySelectorAll(".post-toc li a.nav-link")).map(function(t){var n=document.getElementById(decodeURI(t.getAttribute("href")).replace("#",""));return t.addEventListener("click",function(e){e.preventDefault();e=n.getBoundingClientRect().top+window.scrollY;window.anime({targets:document.scrollingElement,duration:500,easing:"linear",scrollTop:e,complete:function(){history.pushState(null,document.title,t.href)}})}),n})},registerPostReward:function(){var e=document.querySelector(".reward-container button");e&&e.addEventListener("click",function(){document.querySelector(".post-reward").classList.toggle("active")})},activateNavByIndex:function(e){var t=document.querySelectorAll(".post-toc li a.nav-link")[e];if(t&&!t.classList.contains("active-current")){document.querySelectorAll(".post-toc .active").forEach(function(e){e.classList.remove("active","active-current")}),t.classList.add("active","active-current");for(var n=t.parentNode;!n.matches(".post-toc");)n.matches("li")&&n.classList.add("active"),n=n.parentNode;e=document.querySelector(".sidebar-panel-container");e.parentNode.classList.contains("sidebar-toc-active")&&window.anime({targets:e,duration:200,easing:"linear",scrollTop:e.scrollTop-e.offsetHeight/2+t.getBoundingClientRect().top-e.getBoundingClientRect().top})}},updateSidebarPosition:function(){var e,t;window.innerWidth<992||"Pisces"===CONFIG.scheme||"Gemini"===CONFIG.scheme||(e=document.querySelector(".post-toc"),(t="boolean"!=typeof(t=CONFIG.page.sidebar)?"always"===CONFIG.sidebar.display||"post"===CONFIG.sidebar.display&&e:t)&&window.dispatchEvent(new Event("sidebar:show")))},activateSidebarPanel:function(e){var t=document.querySelector(".sidebar-inner"),n=document.querySelector(".sidebar-panel-container"),o=["sidebar-toc-active","sidebar-overview-active"];t.classList.contains(o[e])||window.anime({duration:200,targets:n,easing:"linear",opacity:0,translateY:[0,-20],complete:function(){t.classList.replace(o[1-e],o[e]),window.anime({duration:200,targets:n,easing:"linear",opacity:[0,1],translateY:[-20,0]})}})},getScript:function(o){var e=1<arguments.length&&void 0!==arguments[1]?arguments[1]:{};if("function"==typeof e)return this.getScript(o,{condition:2<arguments.length?arguments[2]:void 0}).then(e);var t=e.condition,r=void 0!==t&&t,n=e.attributes,t=(n=void 0===n?{}:n).id,a=void 0===t?"":t,t=n.async,i=void 0!==t&&t,t=n.defer,c=void 0!==t&&t,t=n.crossOrigin,s=void 0===t?"":t,t=n.dataset,l=void 0===t?{}:t,u=_objectWithoutProperties(n,_excluded),e=e.parentNode,d=void 0===e?null:e;return new Promise(function(e,t){var n;r?e():(n=document.createElement("script"),a&&(n.id=a),s&&(n.crossOrigin=s),n.async=i,n.defer=c,Object.assign(n.dataset,l),Object.entries(u).forEach(function(e){var t=_slicedToArray(e,2),e=t[0],t=t[1];n.setAttribute(e,String(t))}),n.onload=e,n.onerror=t,"object"===_typeof(o)?(e=o.url,t=o.integrity,n.src=e,t&&(n.integrity=t,n.crossOrigin="anonymous")):n.src=o,(d||document.head).appendChild(n))})},loadComments:function(t,e){return e?this.loadComments(t).then(e):new Promise(function(n){var e=document.querySelector(t);CONFIG.comments.lazyload&&e?new IntersectionObserver(function(e,t){e[0].isIntersecting&&(n(),t.disconnect())}).observe(e):n()})}},NexT.motion={},NexT.motion.integrator={queue:[],init:function(){return this.queue=[],this},add:function(e){e=e();return CONFIG.motion.async?this.queue.push(e):this.queue=this.queue.concat(e),this},bootstrap:function(){CONFIG.motion.async||(this.queue=[this.queue]),this.queue.forEach(function(e){var t=window.anime.timeline({duration:200,easing:"linear"});e.forEach(function(e){e.deltaT?t.add(e,e.deltaT):t.add(e)})})}},NexT.motion.middleWares={header:function(){var n=[];function e(e,t){n.push({targets:e,opacity:1,top:0,deltaT:1<arguments.length&&void 0!==t&&t?"-=200":"-=0"})}return e(".header"),"Mist"===CONFIG.scheme&&n.push({targets:".logo-line",scaleX:[0,1],duration:500,deltaT:"-=200"}),"Muse"===CONFIG.scheme&&e(".custom-logo-image"),e(".site-title"),e(".site-brand-container .toggle",!0),e(".site-subtitle"),"Pisces"!==CONFIG.scheme&&"Gemini"!==CONFIG.scheme||e(".custom-logo-image"),document.querySelectorAll(".menu-item").forEach(function(e){n.push({targets:e,complete:function(){return e.classList.add("animated","fadeInDown")},deltaT:"-=200"})}),n},subMenu:function(){var e=document.querySelectorAll(".sub-menu .menu-item");return 0<e.length&&e.forEach(function(e){e.classList.add("animated")}),[]},postList:function(){var n=[],e=CONFIG.motion.transition,t=e.post_block,o=e.post_header,r=e.post_body,e=e.coll_header;function a(t,e){t&&document.querySelectorAll(e).forEach(function(e){n.push({targets:e,complete:function(){return e.classList.add("animated",t)},deltaT:"-=100"})})}return a(t,".post-block, .pagination, .comments"),a(e,".collection-header"),a(o,".post-header"),a(r,".post-body"),n},sidebar:function(){var e=document.querySelector(".sidebar"),t=CONFIG.motion.transition.sidebar;return!t||"Pisces"!==CONFIG.scheme&&"Gemini"!==CONFIG.scheme?[]:[{targets:e,complete:function(){return e.classList.add("animated",t)}}]},footer:function(){return[{targets:document.querySelector(".footer"),opacity:1}]}},NexT.boot={},NexT.boot.registerEvents=function(){NexT.utils.registerScrollPercent(),NexT.utils.registerCanIUseTag(),document.querySelector(".site-nav-toggle .toggle").addEventListener("click",function(e){e.currentTarget.classList.toggle("toggle-close");e=document.querySelector(".site-nav");e&&(e.style.setProperty("--scroll-height",e.scrollHeight+"px"),document.body.classList.toggle("site-nav-on"))}),document.querySelectorAll(".sidebar-nav li").forEach(function(e,t){e.addEventListener("click",function(){NexT.utils.activateSidebarPanel(t)})}),window.addEventListener("hashchange",function(){var e=location.hash;""===e||e.match(/%\S{2}/)||(e=document.querySelector('.tabs ul.nav-tabs li a[href="'.concat(e,'"]')))&&e.click()})},NexT.boot.refresh=function(){CONFIG.prism&&window.Prism.highlightAll(),CONFIG.mediumzoom&&window.mediumZoom(".post-body :not(a) > img, .post-body > img",{background:"var(--content-bg-color)"}),CONFIG.lazyload&&window.lozad(".post-body img").observe(),CONFIG.pangu&&window.pangu.spacingPage(),CONFIG.exturl&&NexT.utils.registerExtURL(),NexT.utils.registerCopyCode(),NexT.utils.registerTabsTag(),NexT.utils.registerActiveMenuItem(),NexT.utils.registerLangSelect(),NexT.utils.registerSidebarTOC(),NexT.utils.registerPostReward(),NexT.utils.wrapTableWithBox(),NexT.utils.registerVideoIframe()},NexT.boot.motion=function(){CONFIG.motion.enable&&NexT.motion.integrator.add(NexT.motion.middleWares.header).add(NexT.motion.middleWares.postList).add(NexT.motion.middleWares.sidebar).add(NexT.motion.middleWares.footer).bootstrap(),NexT.utils.updateSidebarPosition()},document.addEventListener("DOMContentLoaded",function(){NexT.boot.registerEvents(),NexT.boot.refresh(),NexT.boot.motion()});var pjax=new Pjax({selectors:["head title",'script[type="application/json"]',".main-inner",".post-toc-wrap",".languages",".pjax"],analytics:!1,cacheBust:!1,scrollTo:!CONFIG.bookmark.enable});document.addEventListener("pjax:success",function(){var e;pjax.executeScripts(document.querySelectorAll("script[data-pjax]")),NexT.boot.refresh(),CONFIG.motion.enable&&NexT.motion.integrator.init().add(NexT.motion.middleWares.subMenu).add(NexT.motion.middleWares.postList).bootstrap(),"remove"!==CONFIG.sidebar.display&&(e=document.querySelector(".post-toc"),document.querySelector(".sidebar-inner").classList.toggle("sidebar-nav-active",e),NexT.utils.activateSidebarPanel(e?0:1),NexT.utils.updateSidebarPosition())});