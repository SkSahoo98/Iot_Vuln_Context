import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import { AIAnalysisPage } from "./components/ai/AIAnalysisPage";
import { DeviceDetailsDrawer } from "./components/devices/DeviceDetailsDrawer";
import { DevicesPage } from "./components/devices/DevicesPage";
import { FindingDetailsDrawer } from "./components/findings/FindingDetailsDrawer";
import { FindingsPage } from "./components/findings/FindingsPage";
import { AppShell } from "./components/layout/AppShell";
import { SystemStatusModal } from "./components/layout/SystemStatusModal";
import { OverviewPage } from "./components/overview/OverviewPage";
import { RiskResearchPage } from "./components/risk/RiskResearchPage";
import { useAsyncData } from "./hooks/useAsyncData";
import type { AppSection } from "./lib/navigation";

export default function App() {
  const loadDevices = useCallback(() => fetchDevices(), []);
  const loadFindings = useCallback(() => fetchFindings(), []);
  const loadRisk = useCallback(() => fetchRisk(), []);
  const loadExperiments = useCallback(() => fetchExperiments(), []);
  const loadHealth = useCallback(() => fetchHealth(), []);

  const devices = useAsyncData(loadDevices, 15000);
  const findings = useAsyncData(loadFindings, 15000);
  const risk = useAsyncData(loadRisk, 15000);
  const experiments = useAsyncData(loadExperiments, 30000);
  const health = useAsyncData(loadHealth, 15000);

  const [section, setSection] = useState<AppSection>("overview");
  const [statusOpen, setStatusOpen] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [deviceDrawerOpen, setDeviceDrawerOpen] = useState(false);
  const [selectedFindingType, setSelectedFindingType] = useState<string | null>(
    null,
  );
  const [findingDrawerOpen, setFindingDrawerOpen] = useState(false);

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

  const openFindingDetails = (findingType: string) => {
    setSelectedFindingType(findingType);
    setFindingDrawerOpen(true);
    setSection("findings");
  };

  const navigateToAi = (findingType?: string) => {
    if (findingType) setSelectedFindingType(findingType);
    setFindingDrawerOpen(false);
    setSection("ai");
  };

  const refreshAll = () => {
    devices.reload();
    findings.reload();
    risk.reload();
    experiments.reload();
    health.reload();
  };

  return (
    <>
      <AppShell
        section={section}
        apiOnline={apiOnline}
        onNavigate={setSection}
        onOpenStatus={() => setStatusOpen(true)}
        onRefresh={refreshAll}
      >
        {section === "overview" ? (
          <OverviewPage
            devicesCount={devices.data?.length ?? 0}
            onlineCount={onlineCount}
            findings={findings.data}
            findingsLoading={findings.loading}
            findingsError={findings.error}
            onRetryFindings={findings.reload}
            risk={risk.data}
            riskLoading={risk.loading}
            riskError={risk.error}
            onRetryRisk={risk.reload}
            experiment={experimentDetail}
            onNavigateFindings={() => setSection("findings")}
            onNavigateRisk={() => setSection("risk")}
            onOpenFinding={openFindingDetails}
          />
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
