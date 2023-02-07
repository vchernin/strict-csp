"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __spreadArray = (this && this.__spreadArray) || function (to, from) {
    for (var i = 0, il = from.length, j = to.length; i < il; i++, j++)
        to[j] = from[i];
    return to;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StrictCsp = void 0;
/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var crypto = __importStar(require("crypto"));
var cheerio = __importStar(require("cheerio"));
/** Module for enabling a hash-based strict Content Security Policy. */
var StrictCsp = /** @class */ (function () {
    function StrictCsp(html) {
        this.$ = cheerio.load(html, {
            decodeEntities: false,
            _useHtmlParser2: true,
            xmlMode: false,
        });
    }
    StrictCsp.prototype.serializeDom = function () {
        return this.$.html();
    };
    /**
     * Returns a strict Content Security Policy for mittigating XSS.
     * For more details read csp.withgoogle.com.
     * If you modify this CSP, make sure it has not become trivially bypassable by
     * checking the policy using csp-evaluator.withgoogle.com.
     *
     * @param scriptHashes A list of sha-256 hashes of trusted inline scripts.
     * @param styleHashes A list of sha-256 hashes of trusted inline styles.
     * @param enableTrustedTypes If Trusted Types should be enabled for scripts.
     * @param enableBrowserFallbacks If fallbacks for older browsers should be
     *   added. This is will not weaken the policy as modern browsers will ignore
     *   the fallbacks.
     * @param enableUnsafeEval If you cannot remove all uses of eval(), you can
     *   still set a strict CSP, but you will have to use the 'unsafe-eval'
     *   keyword which will make your policy slightly less secure.
     */
    StrictCsp.getStrictCsp = function (scriptHashes, styleHashes, 
    // default CSP options
    cspOptions) {
        if (cspOptions === void 0) { cspOptions = {
            enableBrowserFallbacks: true,
            enableTrustedTypes: false,
            enableUnsafeEval: false,
        }; }
        scriptHashes = scriptHashes || [];
        styleHashes = styleHashes || [];
        var strictCspTemplate = {
            // 'strict-dynamic' allows hashed scripts to create new scripts.
            'script-src': __spreadArray(["'strict-dynamic'"], scriptHashes),
            'style-src': __spreadArray([], styleHashes),
            // Restricts `object-src` to disable dangerous plugins like Flash.
            'object-src': ["'none'"],
            // Restricts `base-uri` to block the injection of `<base>` tags. This
            // prevents attackers from changing the locations of scripts loaded from
            // relative URLs.
            'base-uri': ["'self'"],
        };
        // Adds script fallbacks for browsers not compatible to CSP3 and CSP2.
        // These fallbacks are ignored by modern browsers in presence of hashes,
        // and 'strict-dynamic'.
        if (cspOptions.enableBrowserFallbacks) {
            // Fallback for Safari. All modern browsers supporting strict-dynamic will
            // ignore the 'https:' fallback.
            strictCspTemplate['script-src'].push('https:');
            // 'unsafe-inline' is only ignored in presence of a hash or nonce.
            if (scriptHashes.length > 0) {
                strictCspTemplate['script-src'].push("'unsafe-inline'");
            }
        }
        // If enabled, dangerous DOM sinks will only accept typed objects instead of
        // strings.
        if (cspOptions.enableTrustedTypes) {
            strictCspTemplate = __assign(__assign({}, strictCspTemplate), { 'require-trusted-types-for': ["'script'"] });
        }
        // If enabled, `eval()`-calls will be allowed, making the policy slightly
        // less secure.
        if (cspOptions.enableUnsafeEval) {
            strictCspTemplate['script-src'].push("'unsafe-eval'");
        }
        return Object.entries(strictCspTemplate)
            .map(function (_a) {
            var directive = _a[0], values = _a[1];
            return directive + " " + values.join(' ') + ";";
        })
            .join('');
    };
    /**
     * Enables a CSP via a meta tag at the beginning of the document.
     * Warning: It's recommended to set CSP as HTTP response header instead of
     * using a meta tag. Injections before the meta tag will not be covered by CSP
     * and meta tags don't support CSP in report-only mode.
     *
     * @param csp A Content Security Policy string.
     */
    StrictCsp.prototype.addMetaTag = function (csp) {
        var metaTag = this.$('meta[http-equiv="Content-Security-Policy"]');
        if (!metaTag.length) {
            metaTag = cheerio.load('<meta http-equiv="Content-Security-Policy">')('meta');
            metaTag.prependTo(this.$('head'));
        }
        metaTag.attr('content', csp);
    };
    /**
     * Replaces all sourced scripts with a single inline script that can be hashed
     */
    StrictCsp.prototype.refactorSourcedScriptsForHashBasedCsp = function () {
        var _this = this;
        var srcList = this.$(StrictCsp.SOURCED_SCRIPT_SELECTOR)
            .map(function (i, script) {
            var src = _this.$(script).attr('src');
            _this.$(script).remove();
            return src;
        })
            .filter(function (src) { return src !== null; })
            .get();
        var loaderScript = StrictCsp.createLoaderScript(srcList);
        if (!loaderScript) {
            return;
        }
        // const hash = StrictCsp.hashInlineObject(loaderScript);
        // const comment = cheerio.load(`<!-- CSP hash: ${hash} -->`).root();
        // comment.appendTo(this.$('body'));
        var newScript = cheerio.load('<script>')('script');
        newScript.text(loaderScript);
        newScript.appendTo(this.$('body'));
    };
    /**
     * Returns a list of hashes of all inline scripts found in the HTML document.
     */
    StrictCsp.prototype.hashAllInlineScripts = function () {
        var _this = this;
        return this.$(StrictCsp.INLINE_SCRIPT_SELECTOR)
            .map(function (i, elem) { return StrictCsp.hashInlineObject(_this.$(elem).html() || ''); })
            .get();
    };
    /**
     * Returns a list of hashes of all inline styles found in the HTML document.
     */
    StrictCsp.prototype.hashAllInlineStyles = function () {
        var _this = this;
        return this.$(StrictCsp.INLINE_STYLE_SELECTOR)
            .map(function (i, elem) { return StrictCsp.hashInlineObject(_this.$(elem).html() || ''); })
            .get();
    };
    /**
     * Returns JS code for dynamically loading sourced (external) scripts.
     * @param srcList A list of paths for scripts that should be loaded.
     */
    StrictCsp.createLoaderScript = function (srcList) {
        if (!srcList.length) {
            return undefined;
        }
        var srcListFormatted = srcList.map(function (s) { return "'" + s + "'"; }).join();
        return "\n    var scripts = [" + srcListFormatted + "];\n    scripts.forEach(function(scriptUrl) {\n      var s = document.createElement('script');\n      s.src = scriptUrl;\n      s.async = false; // preserve execution order.\n      document.body.appendChild(s);\n    });\n    ";
    };
    /**
     * Calculates a CSP compatible hash of an inline script.
     * @param scriptText Text between opening and closing script tag. Has to
     *     include whitespaces and newlines!
     */
    StrictCsp.hashInlineObject = function (scriptText) {
        var hash = crypto
            .createHash(StrictCsp.HASH_FUNCTION)
            .update(scriptText, 'utf-8')
            .digest('base64');
        return "'" + StrictCsp.HASH_FUNCTION + "-" + hash + "'";
    };
    StrictCsp.HASH_FUNCTION = 'sha256';
    StrictCsp.INLINE_SCRIPT_SELECTOR = 'script:not([src])';
    StrictCsp.INLINE_STYLE_SELECTOR = 'style:not([href])';
    StrictCsp.SOURCED_SCRIPT_SELECTOR = 'script[src]';
    return StrictCsp;
}());
exports.StrictCsp = StrictCsp;
