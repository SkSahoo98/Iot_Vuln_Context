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
