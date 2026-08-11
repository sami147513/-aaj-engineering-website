let csrf='';
const $=id=>document.getElementById(id);

async function api(url,opt={}){
  opt.headers={
    ...(opt.headers||{}),
    'Content-Type':'application/json'
  };
  if(!['GET','HEAD'].includes((opt.method||'GET').toUpperCase()))
    opt.headers['X-CSRF-Token']=csrf;

  const r=await fetch(url,opt);
  const d=await r.json().catch(()=>({}));

  if(!r.ok) throw new Error(d.error||'Request failed');
  return d;
}

async function login(){
  try{
    const d=await api('/api/login',{
      method:'POST',
      body:JSON.stringify({
        username:$('u').value,
        password:$('p').value
      })
    });

    csrf=d.csrf;
    $('who').textContent=`Signed in as ${d.user.username} (${d.user.role})`;
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');

    await loadContent();
  }catch(e){
    $('msg').textContent=e.message;
  }
}

async function loadContent(){
  try{
    const d=await api('/api/content');

    for(const id of [
      'company_email',
      'contact_phone',
      'contact_address',
      'management_message'
    ]){
      $(id).value=d[id]?.value||'';
    }
  }catch(e){
    if(e.message.includes('Authentication'))
      location.reload();
    else
      $('saveMsg').textContent=e.message;
  }
}

async function saveContent(){
  try{
    await api('/api/content',{
      method:'PUT',
      body:JSON.stringify({
        company_email:$('company_email').value,
        contact_phone:$('contact_phone').value,
        contact_address:$('contact_address').value,
        management_message:$('management_message').value
      })
    });

    $('saveMsg').textContent=' Saved.';
  }catch(e){
    $('saveMsg').textContent=' '+e.message;
  }
}

async function loadAudit(){
  try{
    const d=await api('/api/audit');

    $('audit').innerHTML=d.map(x=>`
      <tr>
        <td>${new Date(x.created_at).toLocaleString()}</td>
        <td>${esc(x.username||'system')}</td>
        <td>${esc(x.action)}</td>
        <td>${esc(x.ip||'')}</td>
      </tr>
    `).join('');
  }catch(e){
    alert(e.message);
  }
}

function esc(s){
  return String(s).replace(/[&<>"']/g,c=>({
    '&':'&amp;',
    '<':'&lt;',
    '>':'&gt;',
    '"':'&quot;',
    "'":'&#39;'
  }[c]));
}

async function logout(){
  try{
    await api('/api/logout',{method:'POST'});
  }finally{
    location.reload();
  }
}
