-- ============================================================
--  Essential Water - Politicas de seguridad (RLS)
--  Reemplaza las politicas "allow_all" por acceso segun identidad.
--
--  ANTES de aplicar esto, los usuarios deben estar migrados a
--  Supabase Auth con su rol grabado en app_metadata.rol
--  (valores: 'admin', 'super', 'vendedor').
--
--  Efecto principal: el rol anon (sin sesion iniciada) pierde
--  TODO acceso. Hoy puede leer y escribir las 11 tablas.
-- ============================================================

-- ------------------------------------------------------------
-- 1. Helper: identifica al usuario y lee su rol REAL
--
--    El JWT solo dice quien es (empleado_id). El rol y el estado
--    activo se leen de la tabla empleados, para que los cambios
--    del admin tengan efecto inmediato: si desactiva a alguien,
--    ese usuario pierde el acceso en su siguiente consulta,
--    aunque su token siga vigente.
-- ------------------------------------------------------------
create or replace function public.empleado_actual()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select auth.jwt() -> 'app_metadata' ->> 'empleado_id'
$$;

create or replace function public.rol_actual()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (select e.rol from public.empleados e
      where e.id = public.empleado_actual() and e.activo = true),
    '')
$$;

-- Atajos legibles
create or replace function public.es_admin() returns boolean
language sql stable as $$ select public.rol_actual() = 'admin' $$;

create or replace function public.es_supervisor() returns boolean
language sql stable as $$ select public.rol_actual() in ('admin','super') $$;

-- Usuario activo con rol valido. Un empleado desactivado da falso
-- en todo y por lo tanto no puede leer ni escribir nada.
create or replace function public.es_activo() returns boolean
language sql stable as $$ select public.rol_actual() <> '' $$;


-- ------------------------------------------------------------
-- 2. Borrar las politicas permisivas actuales
-- ------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array[
    'empleados','clientes','productos','proveedores','ventas_detalle',
    'pagos','egresos','pagos_proveedor','aplicacion_pagos','corte_caja',
    'empleados_pagos'
  ] loop
    execute format('drop policy if exists "allow_all" on public.%I', t);
    execute format('alter table public.%I enable row level security', t);
    -- Nadie entra por defecto; abajo se abre lo necesario.
    execute format('revoke all on public.%I from anon', t);
  end loop;
end $$;


-- ------------------------------------------------------------
-- 3. Lectura: cualquier usuario autenticado
--    (refleja el comportamiento actual de la app: todos ven
--     clientes, productos y el historial para trabajar)
-- ------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array[
    'empleados','clientes','productos','proveedores','ventas_detalle',
    'pagos','aplicacion_pagos','corte_caja'
  ] loop
    execute format($f$
      create policy "leer_autenticados" on public.%I
        for select to authenticated using (public.es_activo())
    $f$, t);
  end loop;
end $$;

-- Gastos y pagos a proveedor: solo admin y supervisor.
-- Un vendedor de ruta no tiene por que ver la estructura de costos.
create policy "leer_egresos" on public.egresos
  for select to authenticated using (public.es_supervisor());

create policy "leer_pagos_prov" on public.pagos_proveedor
  for select to authenticated using (public.es_supervisor());

-- Nomina y prestamos: admin, supervisor y Ruta Norte (Luis).
-- Equivale a canAccessEmpleados() en la app.
create policy "leer_emp_pagos" on public.empleados_pagos
  for select to authenticated
  using (
    public.es_supervisor()
    or auth.jwt() -> 'app_metadata' ->> 'usuario' = 'Ruta Norte'
  );


-- ------------------------------------------------------------
-- 4. Escritura: acotada por rol
-- ------------------------------------------------------------

-- Operacion diaria: cualquier usuario autenticado registra
-- ventas, cobros y su distribucion.
create policy "crear_ventas" on public.ventas_detalle
  for insert to authenticated with check (public.es_activo());

create policy "crear_pagos" on public.pagos
  for insert to authenticated with check (public.es_activo());

create policy "crear_aplicaciones" on public.aplicacion_pagos
  for insert to authenticated with check (public.es_activo());

-- Correcciones y anulaciones: solo admin/supervisor.
-- Esto es lo que evita que un vendedor borre su propio faltante.
create policy "corregir_ventas" on public.ventas_detalle
  for update to authenticated using (public.es_supervisor());

create policy "corregir_pagos" on public.pagos
  for update to authenticated using (public.es_supervisor());

create policy "corregir_aplicaciones" on public.aplicacion_pagos
  for update to authenticated using (public.es_supervisor());

-- Clientes: los vendedores pueden crearlos y editarlos en ruta.
create policy "crear_clientes" on public.clientes
  for insert to authenticated with check (public.es_activo());
create policy "editar_clientes" on public.clientes
  for update to authenticated using (public.es_activo());

-- Catalogos: solo admin.
create policy "admin_productos" on public.productos
  for all to authenticated using (public.es_admin()) with check (public.es_admin());

create policy "admin_proveedores" on public.proveedores
  for all to authenticated using (public.es_supervisor()) with check (public.es_supervisor());

-- Usuarios: solo admin. Un vendedor no puede darse permisos.
create policy "admin_empleados" on public.empleados
  for all to authenticated using (public.es_admin()) with check (public.es_admin());

-- Gastos, pagos a proveedor y caja: admin/supervisor.
create policy "escribir_egresos" on public.egresos
  for all to authenticated using (public.es_supervisor()) with check (public.es_supervisor());

create policy "escribir_pagos_prov" on public.pagos_proveedor
  for all to authenticated using (public.es_supervisor()) with check (public.es_supervisor());

create policy "escribir_corte" on public.corte_caja
  for all to authenticated using (public.es_supervisor()) with check (public.es_supervisor());

-- Nomina y prestamos: mismos que pueden leerla.
create policy "escribir_emp_pagos" on public.empleados_pagos
  for all to authenticated
  using (
    public.es_supervisor()
    or auth.jwt() -> 'app_metadata' ->> 'usuario' = 'Ruta Norte'
  )
  with check (
    public.es_supervisor()
    or auth.jwt() -> 'app_metadata' ->> 'usuario' = 'Ruta Norte'
  );


-- ------------------------------------------------------------
-- 5. Borrado: nadie, desde la app.
--    El sistema ya usa banderas (eliminada / anulado) en vez de
--    borrar, y asi queda el rastro de auditoria intacto.
-- ------------------------------------------------------------
-- (No se crea ninguna politica for delete: sin politica, se niega.)


-- ------------------------------------------------------------
-- 6. Eliminar el PIN en texto plano
--    Ejecutar SOLO despues de verificar que el login por Auth
--    funciona para los 8 usuarios.
-- ------------------------------------------------------------
-- alter table public.empleados drop column clave;
