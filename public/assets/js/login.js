(()=>{
  const m=document.getElementById('f-mode');
  const gp=document.getElementById('group-pass'),gm=document.getElementById('group-magic');
  const u=document.getElementById('f-user');
  const p=document.getElementById('f-pass');
  const k=document.getElementById('f-mkey');
  const forget=document.getElementById('forget-link');
  const remember=document.getElementById('f-remember');

  const sync=()=>{
    const pm = m ? (m.value==='password') : true;
    gp&&gp.classList.toggle('d-none',!pm);
    gm&&gm.classList.toggle('d-none',pm);
    if(u)u.required=pm; if(p)p.required=pm; if(k)k.required=!pm;
  };
  if(m){ m.addEventListener('change',sync); }
  sync();

  if(forget){
    forget.addEventListener('click', (e)=>{
      e.preventDefault();
      // Clear cookie client-side and reveal username field
      document.cookie = 'remember_me=; Max-Age=0; path=/;';
      const hidden = document.getElementById('f-user-hidden');
      const box = forget.closest('.remembered-box');
      if(box) box.remove();
      if(hidden) hidden.remove();
      // Insert an editable username field if not present
      if(!document.getElementById('f-user')){
        const parent = document.getElementById('group-pass');
        const wrap = document.createElement('div');
        wrap.className='form-floating mb-3';
        wrap.innerHTML = '<input type="text" class="form-control" id="f-user" name="username" placeholder="username" autocomplete="username" required><label for="f-user">Username</label>';
        parent.insertBefore(wrap, parent.querySelector('.form-floating'));
      }
      if(remember) remember.checked = false;
    });
  }
})();
