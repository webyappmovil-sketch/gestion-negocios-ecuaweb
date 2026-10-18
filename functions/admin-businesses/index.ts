import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

function jsonResponse(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

async function rollbackCreatedBusiness(admin: ReturnType<typeof createClient>, businessId: string, invitedUserId?: string) {
  const { error: businessError } = await admin.from('businesses').delete().eq('id', businessId);
  if (businessError) console.error('No se pudo revertir el negocio creado parcialmente.', businessError.message);
  if (invitedUserId) {
    const { error: userError } = await admin.auth.admin.deleteUser(invitedUserId);
    if (userError) console.error('No se pudo revertir la invitación creada parcialmente.', userError.message);
  }
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (request.method !== 'POST') return jsonResponse(405, { error: 'Método no permitido.' });

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error('Faltan variables de entorno obligatorias para la función administrativa.');
    return jsonResponse(500, { error: 'El servicio administrativo no está configurado.' });
  }

  const authorization = request.headers.get('Authorization');
  if (!authorization?.startsWith('Bearer ')) return jsonResponse(401, { error: 'Inicia sesión para continuar.' });

  const caller = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: authData, error: authError } = await caller.auth.getUser();
  if (authError || !authData.user) return jsonResponse(401, { error: 'La sesión no es válida o ha caducado.' });

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: administrator, error: administratorError } = await admin
    .from('platform_admins')
    .select('user_id')
    .eq('user_id', authData.user.id)
    .maybeSingle();
  if (administratorError) {
    console.error('No se pudo comprobar el rol de administrador.', administratorError.message);
    return jsonResponse(500, { error: 'No se pudo comprobar el permiso de administrador.' });
  }
  if (!administrator) return jsonResponse(403, { error: 'Esta cuenta no tiene permisos de administrador.' });

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(400, { error: 'La solicitud no contiene JSON válido.' });
  }

  const action = body.action;
  if (action === 'list') {
    const { data, error } = await admin
      .from('businesses')
      .select('id, name, status, created_at, business_memberships(user_id, role)')
      .order('created_at', { ascending: false });
    if (error) {
      console.error('No se pudieron listar los negocios.', error.message);
      return jsonResponse(500, { error: 'No se pudo cargar la lista de negocios.' });
    }
    const { data: users, error: usersError } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
    if (usersError) {
      console.error('No se pudieron leer los correos de los usuarios.', usersError.message);
      return jsonResponse(500, { error: 'No se pudieron cargar los correos de los negocios.' });
    }
    const emailById = new Map<string, string>(
      (users.users || []).map((user) => [user.id, user.email || ''] as [string, string]),
    );
    return jsonResponse(200, {
      businesses: (data || []).map((business) => ({
        id: business.id,
        name: business.name,
        status: business.status,
        created_at: business.created_at,
        members: (business.business_memberships || []).map((membership) => ({
          email: emailById.get(membership.user_id) || '',
          role: membership.role,
        })),
      })),
    });
  }

  const email = typeof authData.user.email === 'string' ? authData.user.email : '';
  const password = typeof body.admin_password === 'string' ? body.admin_password : '';
  if (!email || !password) return jsonResponse(400, { error: 'Confirma tu contraseña de administrador.' });

  const passwordCheck = createClient(supabaseUrl, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: verified, error: passwordError } = await passwordCheck.auth.signInWithPassword({ email, password });
  if (passwordError || verified.user?.id !== authData.user.id) {
    return jsonResponse(401, { error: 'La contraseña de administrador no es correcta.' });
  }

  if (action === 'create') {
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const invitedEmail = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const representative = typeof body.representative === 'string' ? body.representative.trim() : '';
    const phone = typeof body.phone === 'string' ? body.phone.trim() : '';
    const openingDays = typeof body.opening_days === 'number' ? body.opening_days : Number(body.opening_days);
    if (name.length < 2 || name.length > 160
      || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(invitedEmail)
      || representative.length > 160 || phone.length > 40
      || !Number.isInteger(openingDays) || openingDays < 1 || openingDays > 31) {
      return jsonResponse(400, { error: 'Revisa el nombre, correo, representante, teléfono y días de apertura.' });
    }

    const { data: business, error: createError } = await admin
      .from('businesses')
      .insert({ name, representative, phone, contact_email: invitedEmail, opening_days: openingDays })
      .select('id, name, status, created_at')
      .single();
    if (createError || !business) {
      console.error('No se pudo crear el negocio.', createError?.message);
      return jsonResponse(500, { error: 'No se pudo crear el negocio.' });
    }

    let invitedUserId: string | null = null;
    let newlyInvited = false;
    for (let page = 1; page <= 100; page += 1) {
      const { data: users, error: listError } = await admin.auth.admin.listUsers({ page, perPage: 1000 });
      if (listError) {
        await rollbackCreatedBusiness(admin, business.id);
        console.error('No se pudo comprobar si el correo ya tiene cuenta.', listError.message);
        return jsonResponse(500, { error: 'No se pudo comprobar el correo del usuario.' });
      }
      const existingUser = users.users.find((user) => user.email?.toLowerCase() === invitedEmail);
      if (existingUser) {
        invitedUserId = existingUser.id;
        break;
      }
      if (users.users.length < 1000) break;
    }

    if (!invitedUserId) {
      const appSiteUrl = Deno.env.get('APP_SITE_URL');
      const { data: invitation, error: inviteError } = await admin.auth.admin.inviteUserByEmail(invitedEmail, {
        data: { business_id: business.id, business_name: business.name },
        ...(appSiteUrl ? { redirectTo: appSiteUrl } : {}),
      });
      if (inviteError || !invitation.user) {
        await rollbackCreatedBusiness(admin, business.id);
        console.error('No se pudo invitar al usuario del negocio.', inviteError?.message);
        return jsonResponse(400, { error: inviteError?.message || 'No se pudo enviar la invitación.' });
      }
      invitedUserId = invitation.user.id;
      newlyInvited = true;
    }

    const { error: membershipError } = await admin.from('business_memberships').insert({
      business_id: business.id,
      user_id: invitedUserId,
      role: 'owner',
    });
    if (membershipError) {
      await rollbackCreatedBusiness(admin, business.id, newlyInvited ? invitedUserId || undefined : undefined);
      console.error('No se pudo asignar el negocio al usuario.', membershipError.message);
      return jsonResponse(500, { error: 'No se pudo asignar el usuario al negocio.' });
    }

    const currentYear = new Date().getFullYear();
    const meses = () => Array.from({ length: 12 }, () => ({ anio: currentYear, valor: 0 }));
    const initialState = {
      listaCostos: [],
      listaFacturas: [],
      listaGastos: [],
      listaInversiones: [],
      listaIngresos: [],
      listaEscandallos: [],
      configuracionNegocio: {
        nombre,
        representante,
        phones: phone ? [phone] : [],
        emails: [invitedEmail],
        diasApertura: openingDays,
        diasAperturaMensual: Array(12).fill(openingDays),
      },
      datosPresupuestos: { ventas: meses(), costos: meses(), gastos: meses(), activos: meses() },
      ventasBrutas: 0,
      desgloseVentasTPV: null,
      fechaReporte: new Date().toISOString().slice(0, 10),
    };
    const { error: stateError } = await admin.from('business_app_state').insert({
      business_id: business.id,
      state: initialState,
    });
    if (stateError) {
      await rollbackCreatedBusiness(admin, business.id, newlyInvited ? invitedUserId || undefined : undefined);
      console.error('No se pudo inicializar el estado financiero del negocio.', stateError.message);
      return jsonResponse(500, { error: 'No se pudo inicializar el panel financiero del negocio.' });
    }
    return jsonResponse(200, { business, invited_email: invitedEmail, invitation_sent: newlyInvited });
  }

  const businessId = typeof body.business_id === 'string' ? body.business_id : '';
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(businessId)) {
    return jsonResponse(400, { error: 'El identificador del negocio no es válido.' });
  }

  if (action === 'status') {
    const status = body.status;
    if (status !== 'active' && status !== 'blocked') return jsonResponse(400, { error: 'El estado solicitado no es válido.' });
    const { data: updatedBusiness, error } = await admin
      .from('businesses').update({ status }).eq('id', businessId).select('id').maybeSingle();
    if (error) {
      console.error('No se pudo cambiar el estado del negocio.', error.message);
      return jsonResponse(500, { error: 'No se pudo cambiar el estado del negocio.' });
    }
    if (!updatedBusiness) return jsonResponse(404, { error: 'No se encontró el negocio solicitado.' });
    return jsonResponse(200, { success: true });
  }

  if (action === 'delete') {
    const confirmation = typeof body.confirmation === 'string' ? body.confirmation : '';
    if (confirmation !== 'ELIMINAR') return jsonResponse(400, { error: 'Escribe ELIMINAR para confirmar el borrado.' });
    const { data: deletedBusiness, error } = await admin
      .from('businesses').delete().eq('id', businessId).select('id').maybeSingle();
    if (error) {
      console.error('No se pudo eliminar el negocio.', error.message);
      return jsonResponse(500, { error: 'No se pudo eliminar el negocio.' });
    }
    if (!deletedBusiness) return jsonResponse(404, { error: 'No se encontró el negocio solicitado.' });
    return jsonResponse(200, { success: true });
  }

  return jsonResponse(400, { error: 'La acción administrativa no está reconocida.' });
});
