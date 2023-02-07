/** Module for enabling a hash-based strict Content Security Policy. */
export declare class StrictCsp {
    private static readonly HASH_FUNCTION;
    private static readonly INLINE_SCRIPT_SELECTOR;
    private static readonly INLINE_STYLE_SELECTOR;
    private static readonly SOURCED_SCRIPT_SELECTOR;
    private $;
    constructor(html: string);
    serializeDom(): string;
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
    static getStrictCsp(scriptHashes?: string[], styleHashes?: string[], cspOptions?: {
        enableBrowserFallbacks?: boolean;
        enableTrustedTypes?: boolean;
        enableUnsafeEval?: boolean;
    }): string;
    /**
     * Enables a CSP via a meta tag at the beginning of the document.
     * Warning: It's recommended to set CSP as HTTP response header instead of
     * using a meta tag. Injections before the meta tag will not be covered by CSP
     * and meta tags don't support CSP in report-only mode.
     *
     * @param csp A Content Security Policy string.
     */
    addMetaTag(csp: string): void;
    /**
     * Replaces all sourced scripts with a single inline script that can be hashed
     */
    refactorSourcedScriptsForHashBasedCsp(): void;
    /**
     * Returns a list of hashes of all inline scripts found in the HTML document.
     */
    hashAllInlineScripts(): string[];
    /**
     * Returns a list of hashes of all inline styles found in the HTML document.
     */
    hashAllInlineStyles(): string[];
    /**
     * Returns JS code for dynamically loading sourced (external) scripts.
     * @param srcList A list of paths for scripts that should be loaded.
     */
    static createLoaderScript(srcList: string[]): string | undefined;
    /**
     * Calculates a CSP compatible hash of an inline script.
     * @param scriptText Text between opening and closing script tag. Has to
     *     include whitespaces and newlines!
     */
    static hashInlineObject(scriptText: string): string;
}
