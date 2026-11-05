import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { fetchAssessments } from "./api/assessments";
import {
  fetchDevices,
  fetchExperiment,
  fetchExperiments,
  fetchExplanation,
  fetchFindings,
  fetchHealth,
  fetchRisk,
} from "./api/security";
import type { Device, ExperimentDetail, Explanation } from "./api/types";
import { AssessmentsPage } from "./components/assessments/AssessmentsPage";
import { AIAnalysisPage } from "./components/ai/AIAnalysisPage";
import { DeviceDetailsDrawer } from "./components/devices/DeviceDetailsDrawer";
import { DevicesPage } from "./components/devices/DevicesPage";
import { FindingDetailsDrawer } from "./components/findings/FindingDetailsDrawer";
import { FindingsPage } from "./components/findings/FindingsPage";
import { AssistantPage } from "./components/assistant/AssistantPage";
import { AppShell } from "./components/layout/AppShell";
import { SystemStatusModal } from "./components/layout/SystemStatusModal";
import { MorePage } from "./components/more/MorePage";
import { RiskResearchPage } from "./components/risk/RiskResearchPage";
import { SecurityPage } from "./components/security/SecurityPage";
import { useAnchorScroll } from "./hooks/useAnchorScroll";
import { useAsyncData } from "./hooks/useAsyncData";
import { resolveAppMode } from "./lib/appMode";
import {
  MAX_CONVERSATION_MESSAGES,
  type AssistantMessage,
} from "./lib/assistant/conversation";
import {
  INITIAL_WORKFLOW_STATE,
  type AssistantWorkflowState,
} from "./lib/assistant/workflow";
import {
  DEFAULT_SECTION,
  sectionFromHash,
  type AppSection,
  type NavAnchor,
  type NavRequest,
} from "./lib/navigation";

function initialSection(): AppSection {
  return typeof window === "undefined"
    ? DEFAULT_SECTION
    : sectionFromHash(window.location.hash);
}

export default function App() {
  const loadDevices = useCallback(() => fetchDevices(), []);
  const loadFindings = useCallback(() => fetchFindings(), []);
  const loadRisk = useCallback(() => fetchRisk(), []);
  const loadExperiments = useCallback(() => fetchExperiments(), []);
  const loadHealth = useCallback(() => fetchHealth(), []);
  const loadAssessments = useCallback(() => fetchAssessments(), []);

  const devices = useAsyncData(loadDevices, 15000);
  const findings = useAsyncData(loadFindings, 15000);
  const risk = useAsyncData(loadRisk, 15000);
  const experiments = useAsyncData(loadExperiments, 30000);
  const health = useAsyncData(loadHealth, 15000);
  const assessments = useAsyncData(loadAssessments, 0);

  const [nav, setNav] = useState<{ request: NavRequest; key: number }>(() => ({
    request: { section: initialSection() },
    key: 0,
  }));
  const section = nav.request.section;
  const [anchor, setAnchor] = useState<NavAnchor | null>(null);
  useAnchorScroll(anchor);
  const [statusOpen, setStatusOpen] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [deviceDrawerOpen, setDeviceDrawerOpen] = useState(false);
  const [selectedFindingType, setSelectedFindingType] = useState<string | null>(
    null,
  );
  const [findingDrawerOpen, setFindingDrawerOpen] = useState(false);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<
    string | null
  >(null);

  const navigate = useCallback((request: NavRequest) => {
    if (request.assessmentId) setSelectedAssessmentId(request.assessmentId);
    setNav((previous) => ({ request, key: previous.key + 1 }));
    setAnchor(request.anchor ? { ...request.anchor } : null);
  }, []);
  const goTo = useCallback(
    (target: AppSection) => navigate({ section: target }),
    [navigate],
  );
  const scrollTo = useCallback((target: NavAnchor) => setAnchor({ ...target }), []);

  const [assistantMessages, setAssistantMessages] = useState<AssistantMessage[]>([]);
  const addAssistantMessage = useCallback((message: AssistantMessage) => {
    setAssistantMessages((previous) =>
      [...previous, message].slice(-MAX_CONVERSATION_MESSAGES),
    );
  }, []);
  const [assistantWorkflow, setAssistantWorkflow] =
    useState<AssistantWorkflowState>(INITIAL_WORKFLOW_STATE);
  const assistantWorkflowRef = useRef(assistantWorkflow);
  const getAssistantWorkflow = useCallback(() => assistantWorkflowRef.current, []);
  const updateAssistantWorkflow = useCallback(
    (patch: Partial<AssistantWorkflowState>) => {
      assistantWorkflowRef.current = { ...assistantWorkflowRef.current, ...patch };
      setAssistantWorkflow(assistantWorkflowRef.current);
    },
    [],
  );

  const sectionRef = useRef(section);
  sectionRef.current = section;

  useEffect(() => {
    if (!anchor) window.scrollTo({ top: 0 });
  }, [nav.key]);

  useEffect(() => {
    const hash = `#${section}`;
    if (window.location.hash === hash) return;
    if (!window.location.hash) {
      window.history.replaceState(null, "", hash);
    } else {
      window.location.hash = section;
    }
  }, [section]);

  useEffect(() => {
    const onHashChange = () => {
      const next = sectionFromHash(window.location.hash);
      if (next === sectionRef.current) return;
      setNav((previous) => ({ request: { section: next }, key: previous.key + 1 }));
      setAnchor(null);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const [explanationCache, setExplanationCache] = useState<
    Record<string, Explanation>
  >({});
  const explanationCacheRef = useRef(explanationCache);
  explanationCacheRef.current = explanationCache;
  const [explanationLoading, setExplanationLoading] = useState(false);
  const [explanationError, setExplanationError] = useState<string | null>(null);

  const [experimentDetail, setExperimentDetail] =
    useState<ExperimentDetail | null>(null);
  const [experimentError, setExperimentError] = useState<string | null>(null);
  const [experimentLoading, setExperimentLoading] = useState(false);

  useEffect(() => {
    if (selectedFindingType) return;
    if (risk.data?.items?.length) {
      setSelectedFindingType(risk.data.items[0].finding_type);
      return;
    }
    if (findings.data?.length) {
      setSelectedFindingType(findings.data[0].finding_type);
    }
  }, [findings.data, risk.data, selectedFindingType]);

  useEffect(() => {
    const first = experiments.data?.[0];
    if (!first) {
      setExperimentDetail(null);
      return;
    }

    let cancelled = false;
    setExperimentLoading(true);
    setExperimentError(null);

    fetchExperiment(first.id)
      .then((detail) => {
        if (!cancelled) setExperimentDetail(detail);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setExperimentDetail(null);
          setExperimentError(
            err instanceof Error ? err.message : "Failed to load experiment",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setExperimentLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [experiments.data]);

  const loadExplanationFor = useCallback(
    async (findingType: string, refresh = false) => {
      if (!refresh && explanationCacheRef.current[findingType]) {
        setExplanationError(null);
        return;
      }

      setExplanationLoading(true);
      setExplanationError(null);
      try {
        const result = await fetchExplanation(findingType, { refresh });
        setExplanationCache((prev) => ({ ...prev, [findingType]: result }));
      } catch (err: unknown) {
        setExplanationError(
          err instanceof Error ? err.message : "Failed to load AI explanation",
        );
      } finally {
        setExplanationLoading(false);
      }
    },
    [],
  );

  // Load AI explanation only when on AI screen or finding drawer needs it.
  useEffect(() => {
    if (!selectedFindingType) return;
    if (section !== "ai" && !findingDrawerOpen) return;
    void loadExplanationFor(selectedFindingType, false);
  }, [selectedFindingType, section, findingDrawerOpen, loadExplanationFor]);

  const onlineCount = useMemo(
    () => devices.data?.filter((device) => device.status === "ONLINE").length ?? 0,
    [devices.data],
  );

  const selectedFinding = useMemo(
    () =>
      findings.data?.find((item) => item.finding_type === selectedFindingType) ??
      null,
    [findings.data, selectedFindingType],
  );

  const selectedRiskItem = useMemo(
    () =>
      risk.data?.items.find((item) => item.finding_type === selectedFindingType) ??
      null,
    [risk.data, selectedFindingType],
  );

  const currentExplanation = selectedFindingType
    ? explanationCache[selectedFindingType] ?? null
    : null;

  const appMode = useMemo(() => resolveAppMode(health.data), [health.data]);

  const apiOnline = health.loading
    ? null
    : health.error
      ? false
      : health.data?.status === "ok";

  const aiLabel =
    explanationLoading
      ? "Analyzing…"
      : currentExplanation?.source === "ollama"
        ? "Available"
        : currentExplanation?.source === "fallback"
          ? "Fallback"
          : "Ready on demand";

  const aiOk =
    currentExplanation?.source === "ollama"
      ? true
      : currentExplanation?.source === "fallback"
        ? false
        : null;

  const navigateToAi = (findingType?: string) => {
    if (findingType) setSelectedFindingType(findingType);
    setFindingDrawerOpen(false);
    goTo("ai");
  };

  const deviceContext = devices.data
    ? { total: devices.data.length, online: onlineCount }
    : null;

  const refreshAll = () => {
    devices.reload();
    findings.reload();
    risk.reload();
    experiments.reload();
    health.reload();
    assessments.reload();
  };

  return (
    <>
      <AppShell
        section={section}
        apiOnline={apiOnline}
        onNavigate={goTo}
        onOpenStatus={() => setStatusOpen(true)}
        onRefresh={refreshAll}
        isReadOnly={appMode.isReadOnly}
        modeLabel={appMode.modeLabel}
      >
        {section === "assistant" ? (
          <AssistantPage
            assessments={assessments.data}
            assessmentsError={assessments.error}
            onRetryAssessments={assessments.reload}
            onNavigate={navigate}
            messages={assistantMessages}
            onMessage={addAssistantMessage}
            workflow={assistantWorkflow}
            getWorkflow={getAssistantWorkflow}
            onWorkflowChange={updateAssistantWorkflow}
            onAssessmentCreated={assessments.reload}
            isReadOnly={appMode.isReadOnly}
          />
        ) : null}

        {section === "security" ? (
          <SecurityPage
            key={nav.key}
            assessments={assessments.data}
            assessmentsError={assessments.error}
            onRetryAssessments={assessments.reload}
            deviceContext={deviceContext}
            initialTechnicalOpen={nav.request.securityTechnical}
            onNavigate={navigate}
            onScrollTo={scrollTo}
            onReassessmentCreated={() => assessments.reload()}
            isReadOnly={appMode.isReadOnly}
          />
        ) : null}

        {section === "more" ? (
          <MorePage onNavigate={goTo} onOpenStatus={() => setStatusOpen(true)} />
        ) : null}

        {section === "devices" ? (
          <DevicesPage
            devices={devices.data}
            loading={devices.loading}
            error={devices.error}
            onRetry={devices.reload}
            findings={findings.data ?? []}
            onSelect={(device) => {
              setSelectedDevice(device);
              setDeviceDrawerOpen(true);
            }}
            isReadOnly={appMode.isReadOnly}
          />
        ) : null}

        {section === "history" ? (
          <AssessmentsPage
            key={nav.key}
            assessments={assessments.data}
            loading={assessments.loading}
            error={assessments.error}
            selectedAssessmentId={selectedAssessmentId}
            onSelectAssessment={setSelectedAssessmentId}
            onRefresh={assessments.reload}
            initialComparison={nav.request.comparison}
            onScrollTo={scrollTo}
            onOpenResearch={() => navigate({ section: "risk" })}
            isReadOnly={appMode.isReadOnly}
            activeAssessmentSupported={appMode.activeAssessmentSupported}
            devices={devices.data}
          />
        ) : null}

        {section === "findings" ? (
          <FindingsPage
            findings={findings.data}
            riskItems={risk.data?.items ?? []}
            loading={findings.loading}
            error={findings.error}
            onRetry={findings.reload}
            selectedFindingType={selectedFindingType}
            onSelect={(findingType) => {
              setSelectedFindingType(findingType);
              setFindingDrawerOpen(true);
            }}
          />
        ) : null}

        {section === "risk" ? (
          <RiskResearchPage
            risk={risk.data}
            riskLoading={risk.loading}
            riskError={risk.error}
            onRetryRisk={risk.reload}
            selectedFindingType={selectedFindingType}
            onSelectFinding={setSelectedFindingType}
            experiment={experimentDetail}
            experimentLoading={experimentLoading}
            experimentError={experimentError || experiments.error}
          />
        ) : null}

        {section === "ai" ? (
          <AIAnalysisPage
            findings={findings.data}
            findingsLoading={findings.loading}
            findingsError={findings.error}
            onRetryFindings={findings.reload}
            selectedFindingType={selectedFindingType}
            onSelectFinding={setSelectedFindingType}
            riskItems={risk.data?.items ?? []}
            explanation={currentExplanation}
            explanationLoading={explanationLoading}
            explanationError={explanationError}
            onRegenerate={() => {
              if (selectedFindingType) {
                void loadExplanationFor(selectedFindingType, true);
              }
            }}
          />
        ) : null}
      </AppShell>

      <SystemStatusModal
        open={statusOpen}
        onClose={() => setStatusOpen(false)}
        apiOnline={apiOnline}
        mqttAvailable={Boolean(findings.data?.length)}
        aiLabel={aiLabel}
        aiOk={aiOk}
        riskModel={risk.data?.score_version ?? null}
      />

      <DeviceDetailsDrawer
        device={selectedDevice}
        findings={findings.data ?? []}
        open={deviceDrawerOpen}
        onClose={() => setDeviceDrawerOpen(false)}
        isReadOnly={appMode.isReadOnly}
      />

      <FindingDetailsDrawer
        finding={selectedFinding}
        riskItem={selectedRiskItem}
        explanation={currentExplanation}
        explanationLoading={explanationLoading}
        open={findingDrawerOpen}
        onClose={() => setFindingDrawerOpen(false)}
        onOpenAi={() => navigateToAi(selectedFindingType ?? undefined)}
      />
    </>
  );
}
