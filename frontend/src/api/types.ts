export type BackendHealth = {
  status: string;
  service: string;
  environment?: string;
  read_only_mode?: boolean;
  active_assessment_supported?: boolean;
};

export type DeviceTelemetry = {
  temperature: number;
  humidity: number;
  timestamp: string;
};

export type Device = {
  id: number;
  device_id: string;
  ip_address: string | null;
  mac_address: string | null;
  device_type: string;
  firmware_version: string | null;
  status: string;
  created_at: string | null;
  updated_at: string | null;
  latest_telemetry?: DeviceTelemetry | null;
  is_authorized?: boolean;
};

export type Finding = {
  finding_type: string;
  title: string;
  severity: string;
  confidence: number;
  description: string;
  impact: string;
  recommendation: string;
  evidence: Record<string, unknown>;
};

export type RiskItem = {
  finding_type: string;
  base_severity: string;
  score: number;
  risk_level: string;
  score_version: string;
  calculation_method: string;
  base_severity_contribution: number;
  context_score: number;
  factors: Record<string, number>;
  factor_contributions: Record<
    string,
    {
      normalized_value: number;
      weight: number;
      contribution_to_100: number;
    }
  >;
  evidence: Record<string, unknown>;
};

export type RiskSummary = {
  score_version: string;
  mqtt_broker_host: string;
  mqtt_broker_port: number;
  findings_assessed: number;
  highest_score: number | null;
  highest_level: string | null;
  items: RiskItem[];
};

export type ExperimentSummary = {
  id: string;
  experiment_name: string;
  model_version: string | null;
  status: string | null;
  created_at: string;
  conclusion: string | null;
};

export type ExperimentResult = {
  id: string;
  metric_name: string;
  metric_value: string | number | null;
  model_name: string | null;
  notes: string | null;
  created_at: string;
};

export type ExperimentDetail = {
  id: string;
  experiment_name: string;
  objective: string | null;
  hypothesis: string | null;
  methodology: string | null;
  dataset_version: string | null;
  model_version: string | null;
  parameters: Record<string, unknown> | null;
  start_date: string | null;
  end_date: string | null;
  status: string | null;
  conclusion: string | null;
  created_at: string;
  results: ExperimentResult[];
};

export type ExplanationSource = "ollama" | "fallback";

export type Explanation = {
  finding_id: string;
  summary: string;
  evidence: string[];
  why_it_matters: string;
  iot_context: string;
  risk_explanation: string;
  potential_impact: string;
  attack_scenario: string;
  remediation: string[];
  source?: ExplanationSource | string | null;
  model?: string | null;
  generated_at?: string | null;
};

export type AssessmentStatus =
  | "RUNNING"
  | "COMPLETE"
  | "INCOMPLETE"
  | "FAILED";

export type AssessmentType = "MULTI_LAYER" | "ENVIRONMENT";

export type AssessmentSeverity =
  | "INFO"
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type AssessmentRiskLevel =
  | "LOW"
  | "MODERATE"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type AssessmentCreateRequest = {
  target?: string;
  scope?: "AUTHORIZED_IOT" | "SINGLE_DEVICE";
  device_ids?: string[];
};

export type AssessmentEvidence = {
  id: string;
  assessment_id: string;
  target: string;
  port: number | null;
  check_type: string;
  result: string;
  evidence_source: string;
  observation: Record<string, unknown>;
  observed_at: string;
};

export type AssessmentFinding = {
  id: string;
  assessment_id: string;
  finding_id: string;
  finding_type: string;
  category: string;
  title: string;
  severity: AssessmentSeverity;
  confidence: number | null;
  description: string | null;
  target: string;
  port: number | null;
  evidence_reference: string | null;
  remediation: string | null;
  status: string;
  created_at: string;
};

export type RiskFactorContribution = {
  normalized_value: number;
  weight: number;
  contribution_to_100: number;
};

export type RiskSnapshot = {
  id: string;
  assessment_id: string;
  finding_ref: string | null;
  score: number;
  risk_level: AssessmentRiskLevel;
  score_version: string;
  base_severity: AssessmentSeverity | null;
  context_score: number | null;
  factor_contributions: Record<string, RiskFactorContribution>;
  context_inputs: Record<string, unknown>;
  created_at: string;
};

export type AssessmentMetadata = Record<string, unknown>;

export type AssessmentSummary = {
  id: string;
  target: string;
  assessment_type: AssessmentType;
  status: AssessmentStatus;
  started_at: string;
  completed_at: string | null;
  error_summary: string | null;
  metadata: AssessmentMetadata;
  created_at: string;
  evidence_count: number;
  finding_count: number;
  highest_risk: number | null;
  highest_risk_level: AssessmentRiskLevel | null;
};

export type RiskTraceFactor = {
  factor: string;
  rule: "FINDING_TYPE" | "OPEN_PORT_EVIDENCE" | "CONFIGURATION";
  finding_refs: string[];
  evidence_refs: string[];
};

/** Backend-derived links between recorded rows; carries no scores. */
export type RiskTrace = {
  score_version: string;
  overall_rule: "HIGHEST_FINDING_RISK";
  overall_finding_refs: string[];
  factors: RiskTraceFactor[];
};

export type AssessmentDetail = AssessmentSummary & {
  evidence: AssessmentEvidence[];
  findings: AssessmentFinding[];
  risk_snapshots: RiskSnapshot[];
  risk_trace?: RiskTrace | null;
};

export type AssetAssessmentSummary = {
  asset_id: string;
  asset_category: "IOT_DEVICE" | "IOT_INFRASTRUCTURE" | string;
  asset_type: string;
  subtype?: string | null;
  device_id?: string;
  device_type?: string;
  ip_address: string;
  target?: string;
  status: AssessmentStatus;
  assessment_id: string;
  highest_risk: number | null;
  highest_risk_level: AssessmentRiskLevel | null;
  finding_count?: number;
  findings_count: number;
  error_summary: string | null;
  status_telemetry?: string;
};

export type DeviceAssessmentSummary = AssetAssessmentSummary;

export type EnvironmentPosture = {
  batch_id: string;
  assessed_at: string;
  assets_assessed?: number;
  assets_completed?: number;
  assets_failed?: number;
  devices_assessed: number;
  devices_completed: number;
  devices_failed: number;
  infrastructure_assessed?: number;
  infrastructure_completed?: number;
  infrastructure_failed?: number;
  overall_risk_score: number | null;
  overall_risk_level: AssessmentRiskLevel | null;
  highest_risk_asset?: string | null;
  highest_risk_device?: string | null;
  highest_device_id?: string | null;
  total_findings: number;
  important_findings: number;
  additional_findings: number;
  asset_summaries?: AssetAssessmentSummary[];
  device_summaries: DeviceAssessmentSummary[];
  infrastructure_summaries?: AssetAssessmentSummary[];
};

export type RemediationStatus =
  | "OPEN"
  | "GUIDANCE_VIEWED"
  | "REMEDIATION_IN_PROGRESS"
  | "READY_FOR_VERIFICATION"
  | "VERIFICATION_PENDING"
  | "VERIFIED_RESOLVED"
  | "PARTIALLY_RESOLVED"
  | "STILL_PRESENT"
  | "VERIFICATION_FAILED"
  | "INCONCLUSIVE";

export type VerificationVerdict =
  | "VERIFIED_RESOLVED"
  | "PARTIALLY_RESOLVED"
  | "STILL_PRESENT"
  | "VERIFICATION_FAILED"
  | "INCONCLUSIVE";

export type RemediationVerification = {
  id: string;
  workflow_id: string;
  verification_assessment_id: string;
  verdict: VerificationVerdict;
  verdict_rationale: string | null;
  coverage_equivalent: boolean;
  baseline_finding_present: boolean;
  evidence_references: string[];
  risk_delta: {
    baseline_score: number | null;
    verification_score: number | null;
    delta: number | null;
    baseline_overall: number | null;
    verification_overall: number | null;
  } | null;
  created_at: string;
};

export type RemediationWorkflow = {
  id: string;
  baseline_assessment_id: string;
  baseline_finding_id: string;
  finding_fingerprint: string;
  target: string;
  status: RemediationStatus;
  guidance_version: string;
  user_confirmed_at: string | null;
  verification_assessment_id: string | null;
  verification_verdict: VerificationVerdict | null;
  verdict_rationale: string | null;
  coverage_summary: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  verifications: RemediationVerification[];
  finding_details?: Record<string, unknown> | null;
};

export type RemediationComparison = {
  workflow: RemediationWorkflow;
  baseline: {
    assessment_id: string;
    target: string;
    started_at: string;
    finding: AssessmentFinding | null;
    risk_snapshot: RiskSnapshot | null;
    evidence: AssessmentEvidence[];
  };
  verification: {
    assessment_id: string;
    target: string;
    status: AssessmentStatus;
    started_at: string;
    finding_found: boolean;
    finding: AssessmentFinding | null;
    risk_snapshot: RiskSnapshot | null;
    evidence: AssessmentEvidence[];
  } | null;
  verdict: string;
  verdict_rationale: string | null;
  coverage_equivalent: boolean;
  risk_delta: {
    baseline_score: number | null;
    verification_score: number | null;
    delta: number | null;
    baseline_overall: number | null;
    verification_overall: number | null;
  } | null;
};
