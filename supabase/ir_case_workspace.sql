-- Additive workspace on existing ir_cases. Run before deploying workspace handler.
-- Fresh installs also need the legacy base table; existing data remains untouched.
CREATE TABLE IF NOT EXISTS public.ir_cases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- Dev ownership is explicit; pre-existing production cases are never backfilled.
CREATE TABLE IF NOT EXISTS public.ir_case_dev_scope (
  case_id uuid PRIMARY KEY REFERENCES public.ir_cases(id) ON DELETE RESTRICT,
  creator_id uuid NOT NULL REFERENCES public.app_users(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ir_case_dev_scope_creator_idx ON public.ir_case_dev_scope (creator_id);
REVOKE ALL ON public.ir_case_dev_scope FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON public.ir_case_dev_scope TO service_role;

-- SECURITY DEFINER inserts both rows in one transaction; exceptions roll both back.
-- Only trusted service_role API may pass authenticated creator ID.
CREATE OR REPLACE FUNCTION public.ir_create_dev_cases(p_cases jsonb, p_creator_id uuid)
RETURNS SETOF public.ir_cases LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE v_username text;
DECLARE v_case public.ir_cases%ROWTYPE;
DECLARE v_input jsonb;
BEGIN
  SELECT username INTO v_username FROM public.app_users WHERE id = p_creator_id;
  IF v_username IS NULL OR jsonb_typeof(p_cases) <> 'array' OR jsonb_array_length(p_cases) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'Invalid case payload';
  END IF;
  FOR v_input IN SELECT value FROM jsonb_array_elements(p_cases) LOOP
    IF jsonb_typeof(v_input) <> 'object'
      OR jsonb_typeof(v_input->'title') <> 'string'
      OR length(btrim(v_input->>'title')) NOT BETWEEN 1 AND 500
      OR (v_input ? 'description' AND jsonb_typeof(v_input->'description') <> 'string')
      OR length(coalesce(v_input->>'description', '')) > 100000
      OR v_input->>'created_by' IS DISTINCT FROM v_username THEN
      RAISE EXCEPTION 'Invalid case payload';
    END IF;
    INSERT INTO public.ir_cases (title, description, created_by)
      VALUES (btrim(v_input->>'title'), btrim(coalesce(v_input->>'description', '')), v_username)
      RETURNING * INTO v_case;
    INSERT INTO public.ir_case_dev_scope(case_id, creator_id) VALUES (v_case.id, p_creator_id);
    RETURN NEXT v_case;
  END LOOP;
END $$;
REVOKE ALL ON FUNCTION public.ir_create_dev_cases(jsonb,uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ir_create_dev_cases(jsonb,uuid) TO service_role;

-- Lock marker row while editing so scope cannot change between check and update.
CREATE OR REPLACE FUNCTION public.ir_update_dev_case(p_case_id uuid, p_title text, p_description text, p_creator_id uuid)
RETURNS public.ir_cases LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE v_case public.ir_cases%ROWTYPE;
BEGIN
  IF length(btrim(coalesce(p_title, ''))) NOT BETWEEN 1 AND 500 OR length(coalesce(p_description, '')) > 100000 THEN
    RAISE EXCEPTION 'Invalid case payload';
  END IF;
  SELECT c.* INTO v_case FROM public.ir_case_dev_scope s
    JOIN public.ir_cases c ON c.id = s.case_id
    WHERE s.case_id = p_case_id AND (p_creator_id IS NULL OR s.creator_id = p_creator_id)
    FOR UPDATE OF s, c;
  IF NOT FOUND THEN RETURN NULL; END IF;
  UPDATE public.ir_cases SET title = btrim(p_title), description = btrim(coalesce(p_description, '')), updated_at = now()
    WHERE id = p_case_id RETURNING * INTO v_case;
  RETURN v_case;
END $$;
REVOKE ALL ON FUNCTION public.ir_update_dev_case(uuid,text,text,uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ir_update_dev_case(uuid,text,text,uuid) TO service_role;
ALTER TABLE public.ir_cases ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'open';
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ir_cases_status_check' AND conrelid = 'public.ir_cases'::regclass) THEN
    ALTER TABLE public.ir_cases ADD CONSTRAINT ir_cases_status_check CHECK (status IN ('open', 'investigating', 'contained', 'closed'));
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS ir_cases_status_created_idx ON public.ir_cases (status, created_at DESC);

CREATE TABLE IF NOT EXISTS public.ir_case_iocs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES public.ir_cases(id) ON DELETE RESTRICT,
  ioc_type text NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url', 'hash')),
  value text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048 AND value = btrim(value)),
  linked_by uuid NOT NULL REFERENCES public.app_users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, ioc_type, value)
);
CREATE INDEX IF NOT EXISTS ir_case_iocs_case_time_idx ON public.ir_case_iocs (case_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS public.ir_case_notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES public.ir_cases(id) ON DELETE RESTRICT,
  body text NOT NULL CHECK (length(btrim(body)) BETWEEN 1 AND 4000),
  author_id uuid NOT NULL REFERENCES public.app_users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ir_case_notes_case_time_idx ON public.ir_case_notes (case_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS public.ir_case_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  case_id uuid NOT NULL REFERENCES public.ir_cases(id) ON DELETE RESTRICT,
  event_type text NOT NULL CHECK (event_type IN ('status', 'note', 'ioc')),
  actor_id uuid NOT NULL REFERENCES public.app_users(id) ON DELETE RESTRICT,
  detail text NOT NULL CHECK (length(detail) BETWEEN 1 AND 2048),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ir_case_events_case_id_idx ON public.ir_case_events (case_id, id DESC);

-- Events for notes/IOCs are transactional; status update event written by API RPC below.
CREATE OR REPLACE FUNCTION public.ir_workspace_log_insert() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.ir_case_events(case_id,event_type,actor_id,detail)
  VALUES (NEW.case_id, 'note', NEW.author_id, 'Note added');
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS ir_case_notes_log ON public.ir_case_notes;
CREATE TRIGGER ir_case_notes_log AFTER INSERT ON public.ir_case_notes FOR EACH ROW EXECUTE FUNCTION public.ir_workspace_log_insert();
DROP TRIGGER IF EXISTS ir_case_iocs_log ON public.ir_case_iocs;
CREATE OR REPLACE FUNCTION public.ir_workspace_log_ioc_insert() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.ir_case_events(case_id,event_type,actor_id,detail)
  VALUES (NEW.case_id, 'ioc', NEW.linked_by, NEW.ioc_type || ': ' || NEW.value);
  RETURN NEW;
END $$;
CREATE TRIGGER ir_case_iocs_log AFTER INSERT ON public.ir_case_iocs FOR EACH ROW EXECUTE FUNCTION public.ir_workspace_log_ioc_insert();

CREATE OR REPLACE FUNCTION public.ir_workspace_set_status(p_case_id uuid, p_status text, p_actor_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE old_status text;
BEGIN
  IF p_status IS NULL OR p_status NOT IN ('open','investigating','contained','closed') THEN RAISE EXCEPTION 'Invalid status'; END IF;
  SELECT status INTO old_status FROM public.ir_cases WHERE id = p_case_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Case not found'; END IF;
  IF old_status = p_status THEN RETURN; END IF;
  UPDATE public.ir_cases SET status = p_status, updated_at = now() WHERE id = p_case_id;
  INSERT INTO public.ir_case_events(case_id,event_type,actor_id,detail)
  VALUES (p_case_id,'status',p_actor_id,old_status || ' → ' || p_status);
END $$;

CREATE OR REPLACE FUNCTION public.ir_workspace_set_dev_status(p_case_id uuid, p_status text, p_actor_id uuid, p_creator_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE old_status text;
BEGIN
  IF p_status IS NULL OR p_status NOT IN ('open','investigating','contained','closed') THEN RAISE EXCEPTION 'Invalid status'; END IF;
  SELECT c.status INTO old_status FROM public.ir_case_dev_scope s
    JOIN public.ir_cases c ON c.id = s.case_id
    WHERE s.case_id = p_case_id AND (p_creator_id IS NULL OR s.creator_id = p_creator_id)
    FOR UPDATE OF s, c;
  IF NOT FOUND THEN RETURN; END IF;
  IF old_status = p_status THEN RETURN; END IF;
  UPDATE public.ir_cases SET status = p_status, updated_at = now() WHERE id = p_case_id;
  INSERT INTO public.ir_case_events(case_id,event_type,actor_id,detail)
  VALUES (p_case_id,'status',p_actor_id,old_status || ' → ' || p_status);
END $$;
REVOKE ALL ON FUNCTION public.ir_workspace_set_dev_status(uuid,text,uuid,uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ir_workspace_set_dev_status(uuid,text,uuid,uuid) TO service_role;

CREATE OR REPLACE FUNCTION public.ir_workspace_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Workspace history is append-only'; END $$;
DROP TRIGGER IF EXISTS ir_case_notes_immutable ON public.ir_case_notes;
CREATE TRIGGER ir_case_notes_immutable BEFORE UPDATE OR DELETE ON public.ir_case_notes FOR EACH ROW EXECUTE FUNCTION public.ir_workspace_immutable();
DROP TRIGGER IF EXISTS ir_case_events_immutable ON public.ir_case_events;
CREATE TRIGGER ir_case_events_immutable BEFORE UPDATE OR DELETE ON public.ir_case_events FOR EACH ROW EXECUTE FUNCTION public.ir_workspace_immutable();

REVOKE ALL ON public.ir_case_iocs, public.ir_case_notes, public.ir_case_events FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.ir_workspace_set_status(uuid,text,uuid) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.ir_workspace_log_insert() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.ir_workspace_log_ioc_insert() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.ir_workspace_immutable() FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON public.ir_case_iocs, public.ir_case_notes, public.ir_case_events TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.ir_case_events_id_seq TO service_role;
GRANT EXECUTE ON FUNCTION public.ir_workspace_set_status(uuid,text,uuid) TO service_role;
-- No RLS claim: service_role bypasses RLS. API enforces ownership; direct service-role access remains privileged.
