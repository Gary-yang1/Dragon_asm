import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { parseURLAuthorization, scopeTargetInputs, validateURLRule } from '../pages/discovery/urlAuthorization';
import { URLRuleEditor } from '../pages/discovery/URLRuleEditor';

describe('URL authorization', () => {
  it('removes the wildcard before passing a hostname to the browser parser', () => {
    const NativeURL = globalThis.URL;
    class StrictHostURL extends NativeURL {
      constructor(input: string, base?: string | URL) {
        if (input.includes('*.')) throw new Error('browser encodes wildcard host');
        super(input, base);
      }
    }
    vi.stubGlobal('URL', StrictHostURL);
    try {
      expect(parseURLAuthorization('https://*.example.com:8443').rule).toEqual({
        protocol:'https',include_root:false,include_subdomains:true,ports:[8443]
      });
    } finally { vi.unstubAllGlobals(); }
  });
  it('converts pasted wildcard URLs and keeps root inclusion explicit', () => {
    const result = parseURLAuthorization('https://*.example.com:8443');
    expect(result.value).toBe('https://example.com');
    expect(result.rule).toEqual({protocol:'https',include_root:false,include_subdomains:true,ports:[8443]});
    expect(scopeTargetInputs({target_type:'url',value:result.value,url_rule:result.rule,match_mode:'include',coverage_mode:'exact'})).toEqual([]);
  });
  it('expands only permitted concrete origins and reports discarded paths', () => {
    const result = parseURLAuthorization('http://example.com/admin?x=1');
    expect(result.discardedPath).toBe(true);
    expect(scopeTargetInputs({target_type:'url',value:result.value,url_rule:{...result.rule,protocol:'both',ports:[]},match_mode:'include',coverage_mode:'exact'})).toEqual([
      {type:'url',value:'http://example.com:80'},{type:'url',value:'https://example.com:443'}
    ]);
    expect(() => parseURLAuthorization('https://*.*.example.com')).toThrow();
    expect(() => parseURLAuthorization('https://*.127.0.0.1')).toThrow();
  });
  it('validates empty host selection and invalid ports', () => {
    expect(validateURLRule({protocol:'https',include_root:false,include_subdomains:false,ports:[]})).toBeTruthy();
    expect(validateURLRule({protocol:'https',include_root:true,include_subdomains:false,ports:[65536]})).toBeTruthy();
  });
  it('provides explicit host switches and commits a custom port list', async () => {
    const changed = vi.fn();
    render(<URLRuleEditor id="rule" value={{protocol:'https',include_root:false,include_subdomains:true,ports:[]}} onChange={changed}/>);
    expect(screen.getByRole('checkbox',{name:'包含当前主机'})).not.toBeChecked();
    await userEvent.click(screen.getByRole('checkbox',{name:'包含当前主机'}));
    expect(changed).toHaveBeenLastCalledWith(expect.objectContaining({include_root:true}));
    await userEvent.type(screen.getByLabelText('URL 允许端口'), '443,8443');
    fireEvent.blur(screen.getByLabelText('URL 允许端口'));
    expect(changed).toHaveBeenLastCalledWith(expect.objectContaining({ports:[443,8443]}));
  });
});
