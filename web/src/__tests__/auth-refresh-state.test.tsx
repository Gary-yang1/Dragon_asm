import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useEffect, useState } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { http as mockHTTP, HttpResponse, delay } from 'msw';
import { describe, expect, it, vi } from 'vitest';
import { AuthProvider, useAuth } from '../auth/AuthProvider';
import { RequireAuth } from '../auth/RequireAuth';
import { Permission } from '../auth/permissions';
import { postJSON } from '../api/http';
import { server } from '../test/server';
import { ProjectWorkspaceProvider } from '../projects/ProjectContext';
import { RequirePermission } from '../auth/RequirePermission';

describe('silent session refresh', () => {
  it('keeps an in-flight form mounted while rechecking current permissions', async () => {
    let attempts=0, refreshed=false, capabilityReads=0;
    const mounted=vi.fn(), completed=vi.fn();
    server.use(
      mockHTTP.get('/api/v1/auth/me',async()=>{if(refreshed)await delay(35);return HttpResponse.json({data:{id:'u1',username:'alice',display_name:'Alice',tenant_id:'t',org_id:'o',must_change_password:false}});}),
      mockHTTP.get('/api/v1/auth/permissions',()=>HttpResponse.json({data:{permissions:refreshed?[Permission.DiscoveryRead]:[Permission.DiscoveryRead,Permission.DiscoveryRun]}})),
      mockHTTP.get('/api/v1/projects/1/capabilities',async()=>{capabilityReads++;if(refreshed)await delay(35);return HttpResponse.json({data:{role:'project_owner',project_status:'active',permissions:[Permission.DiscoveryRead]}});}),
      mockHTTP.post('/api/v1/auth/refresh',()=>{refreshed=true;return HttpResponse.json({data:{access_token:'renewed',refresh_token:'renewed-refresh'}});}),
      mockHTTP.post('/api/v1/refresh-test-action',async()=>{
        attempts++;
        if(attempts===1)return HttpResponse.json({error:{code:'UNAUTHORIZED',message:'expired'}},{status:401});
        await delay(100);
        return HttpResponse.json({data:{ok:true}});
      })
    );
    localStorage.setItem('asm.auth',JSON.stringify({user:{id:'u1',username:'alice',displayName:'Alice',role:'project_owner',projectId:1},accessToken:'old',refreshToken:'refresh',permissions:[Permission.DiscoveryRead,Permission.DiscoveryRun]}));
    function FormProbe(){
      const [value,setValue]=useState('');
      const [done,setDone]=useState(false);
      const {can}=useAuth();
      useEffect(()=>{mounted();},[]);
      return <><input aria-label="draft" value={value} onChange={event=>setValue(event.target.value)}/>
        <button onClick={()=>{void postJSON('/refresh-test-action',{}).then(()=>{completed();setDone(true);});}}>submit</button>
        <button disabled={!can(Permission.DiscoveryRun)}>current permission</button>
        {done && <span>request complete</span>}</>;
    }
    render(<MemoryRouter initialEntries={['/projects/1/discovery']}><AuthProvider><RequireAuth><ProjectWorkspaceProvider><RequirePermission permission={Permission.DiscoveryRead}><FormProbe/></RequirePermission></ProjectWorkspaceProvider></RequireAuth></AuthProvider></MemoryRouter>);
    await userEvent.type(await screen.findByLabelText('draft'),'unsaved content');
    await userEvent.click(screen.getByRole('button',{name:'submit'}));
    await waitFor(()=>expect(completed).toHaveBeenCalledOnce());
    expect(mounted).toHaveBeenCalledOnce();
    expect(screen.getByLabelText('draft')).toHaveValue('unsaved content');
    expect(screen.getByText('request complete')).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'current permission'})).toBeDisabled();
    expect(capabilityReads).toBeGreaterThanOrEqual(2);
  });
});
