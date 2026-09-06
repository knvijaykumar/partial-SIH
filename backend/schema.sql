-- ==============================================================================
-- SIH26106: AI-Powered Email Threat Detection & Forensic Platform Schema
-- ==============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Investigations Table
CREATE TABLE IF NOT EXISTS public.investigations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT NOT NULL,
    subject TEXT,
    sender TEXT,
    recipient TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    ai_label TEXT,
    ai_score DOUBLE PRECISION,
    status TEXT DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Email Forensics Table
CREATE TABLE IF NOT EXISTS public.email_forensics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    date TEXT,
    reply_to TEXT,
    return_path TEXT,
    message_id TEXT,
    spf_status TEXT,
    dkim_status TEXT,
    dmarc_status TEXT,
    authentication_results TEXT,
    received_headers JSONB DEFAULT '[]'::jsonb,
    headers JSONB DEFAULT '{}'::jsonb,
    body_plain TEXT,
    body_html TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 3. URL Intelligence Table
CREATE TABLE IF NOT EXISTS public.url_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    protocol TEXT,
    hostname TEXT,
    domain TEXT,
    port INTEGER,
    path TEXT,
    suspicious BOOLEAN DEFAULT false,
    indicators JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. Domain Intelligence Table
CREATE TABLE IF NOT EXISTS public.domain_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    available BOOLEAN DEFAULT true,
    handle TEXT,
    status JSONB DEFAULT '[]'::jsonb,
    events JSONB DEFAULT '{}'::jsonb,
    nameservers JSONB DEFAULT '[]'::jsonb,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 5. IP Intelligence Table
CREATE TABLE IF NOT EXISTS public.ip_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    version INTEGER,
    public BOOLEAN,
    private BOOLEAN,
    loopback BOOLEAN,
    reserved BOOLEAN,
    country TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    isp TEXT,
    organization TEXT,
    abuse_confidence_score INTEGER,
    total_reports INTEGER,
    reputation_error TEXT,
    raw_geoip JSONB DEFAULT '{}'::jsonb,
    raw_reputation JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 6. Attachment Intelligence Table
CREATE TABLE IF NOT EXISTS public.attachment_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    filename TEXT,
    extension TEXT,
    content_type TEXT,
    detected_mime_type TEXT,
    size_bytes BIGINT,
    sha256 TEXT NOT NULL,
    risky BOOLEAN DEFAULT false,
    indicators JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 7. Forensic Evidence Table
CREATE TABLE IF NOT EXISTS public.forensic_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    risk_score INTEGER,
    risk_level TEXT,
    conclusion TEXT,
    positive_signals JSONB DEFAULT '[]'::jsonb,
    negative_signals JSONB DEFAULT '[]'::jsonb,
    evidence_items JSONB DEFAULT '[]'::jsonb,
    explanation_method TEXT,
    threat_correlation JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 8. Attack Graphs Table
CREATE TABLE IF NOT EXISTS public.attack_graphs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    node_count INTEGER DEFAULT 0,
    edge_count INTEGER DEFAULT 0,
    nodes JSONB DEFAULT '[]'::jsonb,
    edges JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- ==============================================================================
-- INDEXES FOR FAST QUERYING
-- ==============================================================================
CREATE INDEX IF NOT EXISTS idx_email_forensics_investigation_id ON public.email_forensics(investigation_id);
CREATE INDEX IF NOT EXISTS idx_url_intel_investigation_id ON public.url_intelligence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_domain_intel_investigation_id ON public.domain_intelligence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_ip_intel_investigation_id ON public.ip_intelligence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_attachment_intel_investigation_id ON public.attachment_intelligence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_attachment_intel_sha256 ON public.attachment_intelligence(sha256);
CREATE INDEX IF NOT EXISTS idx_forensic_evidence_investigation_id ON public.forensic_evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_attack_graphs_investigation_id ON public.attack_graphs(investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON public.investigations(created_at DESC);

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) & ACCESS PERMISSIONS
-- ==============================================================================
-- Enable RLS
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_forensics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.url_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domain_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ip_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attachment_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.forensic_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_graphs ENABLE ROW LEVEL SECURITY;

-- Create Policies for Full Read/Write Access by API / Backend
CREATE POLICY "Allow all operations for anon and service_role" ON public.investigations FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations for anon and service_role" ON public.email_forensics FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations for anon and service_role" ON public.url_intelligence FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations for anon and service_role" ON public.domain_intelligence FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations for anon and service_role" ON public.ip_intelligence FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations for anon and service_role" ON public.attachment_intelligence FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations for anon and service_role" ON public.forensic_evidence FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations for anon and service_role" ON public.attack_graphs FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

-- Grant schema usage and table privileges
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
