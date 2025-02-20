/*
    This library allows serialization/deserialization of structures having to do with
    Keylime push model. In particular, it provides methods to serialize/deserialize
    structures required to implement next OpenAPI spec:
    openapi: 3.0.0
info:
  title: Capabilities Negotiation API
  version: 1.0.0
components:
  schemas:
    AttestationRequest: # Request schema
      type: object
      properties:
        data:
          type: object
          properties:
            type:
              type: string
              example: attestation
            attributes:
              type: object
              properties:
                evidence_supported:
                  type: array
                  items:
                    type: object
                    properties:
                      evidence_class:
                        type: string
                        example: certification
                      evidence_type:
                        type: string
                        example: tpm_quote
                      agent_capabilities:
                        type: object
                        properties:
                          spec_version:
                            type: string
                            example: "2.0"
                          hash_algorithms:
                            type: array
                            items:
                              type: string
                              example: sha3_512
                          signing_schemes:
                            type: array
                            items:
                              type: string
                              example: rsassa
                          attestation_keys:
                            type: array
                            items:
                              type: object
                              properties:
                                key_class:
                                  type: string
                                  example: private_key
                                key_identifier:
                                  type: string
                                  example: "attestation_key_identifier"
                                key_algorithm:
                                  type: string
                                  example: rsa
                                public_hash:
                                  type: string
                                  example: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"
                        required:
                          - spec_version
                          - hash_algorithms
                          - signing_schemes
                          - attestation_keys
                      version:  # Only present for some evidence types
                        type: string
                        example: "2.1"
                boot_time:
                  type: string
                  format: date-time
                  example: "2024-11-12T16:21:17Z"
              required:
                - evidence_supported
                - boot_time
          required:
            - type
            - attributes
      required:
        - data
    AttestationResponse: # Response schema
      type: object
      properties:
        data:
          type: object
          properties:
            type:
              type: string
              example: attestation
            attributes:
              type: object
              properties:
                evidence_collected: # Nuevo campo para la respuesta
                  type: array
                  items:
                    type: object
                    properties:
                      evidence_class:
                        type: string
                        example: certification
                      evidence_type:
                        type: string
                        example: tpm_quote
                      chosen_parameters:
                        type: object
                        properties:
                          nonce:
                            type: string
                            example: "here_the_nonce"
                          pcr_selection:
                            type: array
                            items:
                              type: integer
                              example: 0
                          hash_algorithm:
                            type: string
                            example: sha384
                          signing_scheme:
                            type: string
                            example: rsassa
                          attestation_key:
                            type: object
                            properties:
                              key_class:
                                type: string
                                example: private_key
                              key_identifier:
                                type: string
                                example: "attestation_key_identifier"
                              key_algorithm:
                                type: string
                                example: rsa
                              public_hash:
                                type: string
                                example: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"
                          starting_offset: # Only for some evidence types
                            type: integer
                            example: 25
                boot_time:
                  type: string
                  format: date-time
                  example: "2024-11-12T16:21:17Z"
              required:
                - evidence_collected
                - boot_time
          required:
            - type
            - attributes
      required:
        - data
paths:
  /agents/{id}/attestations:
    post:
      summary: Create Attestation Data for Agent
      parameters:
        - in: path
          name: id
          schema:
            type: string
          required: true
          description: ID of the agent
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AttestationRequest' # Usa AttestationRequest
      responses:
        '201':
          description: Attestation data created successfully
        '200':
          description: Attestation data retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AttestationResponse' # Usa AttestationResponse
        '400':
          description: Bad request (e.g., invalid input)
        # other possible response codes
*/

use serde::{Deserialize, Serialize};

// Define the structure for the AttestationRequest:
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationRequest {
    #[serde(rename(serialize = "data", deserialize = "data"))]
    pub data: RequestData,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct RequestData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
    pub attributes: Attributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Attributes {
    pub evidence_supported: Vec<EvidenceSupported>,
    pub boot_time: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceSupported {
    pub evidence_class: String,
    pub evidence_type: String,
    pub agent_capabilities: AgentCapabilities,
    pub version: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AgentCapabilities {
    pub spec_version: String,
    pub hash_algorithms: Vec<String>,
    pub signing_schemes: Vec<String>,
    pub attestation_keys: Vec<AttestationKeys>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationKeys {
    pub key_class: String,
    pub key_identifier: String,
    pub key_algorithm: String,
    pub public_hash: String,
}

// Define the structure for the AttestationResponse:
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationResponse {
    #[serde(rename(serialize = "data", deserialize = "data"))]
    pub data: ResponseData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
    pub attributes: ResponseAttributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseAttributes {
    pub evidence_collected: Vec<EvidenceCollected>,
    pub boot_time: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceCollected {
    pub evidence_class: String,
    pub evidence_type: String,
    pub chosen_parameters: ChosenParameters,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChosenParameters {
    pub nonce: String,
    pub pcr_selection: Vec<i32>,
    pub hash_algorithm: String,
    pub signing_scheme: String,
    pub attestation_key: AttestationKey,
    pub starting_offset: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationKey {
    pub key_class: String,
    pub key_identifier: String,
    pub key_algorithm: String,
    pub public_hash: String,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_request() {
        // Create a new AttestationRequest object and serialize it to JSON
        let request = AttestationRequest {
            data: RequestData {
                type_: "attestation".to_string(),
                attributes: Attributes {
                    evidence_supported: vec![
                        EvidenceSupported {
                            evidence_class: "certification".to_string(),
                            evidence_type: "tpm_quote".to_string(),
                            agent_capabilities: AgentCapabilities {
                                spec_version: "2.0".to_string(),
                                hash_algorithms: vec!["sha3_512".to_string()],
                                signing_schemes: vec!["rsassa".to_string()],
                                attestation_keys: vec![
                                    AttestationKeys {
                                        key_class: "private_key".to_string(),
                                        key_identifier: "att_key_identifier".to_string(),
                                        key_algorithm: "rsa".to_string(),
                                        public_hash: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411".to_string(),
                                    },
                                ],
                            },
                            version: Some("2.1".to_string()),
                        },
                    ],
                    boot_time: "2024-11-12T16:21:17Z".to_string(),
                },
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        println!("{}", json);
        assert_eq!(json, r#"{"data":{"type":"attestation","attributes":{"evidence_supported":[{"evidence_class":"certification","evidence_type":"tpm_quote","agent_capabilities":{"spec_version":"2.0","hash_algorithms":["sha3_512"],"signing_schemes":["rsassa"],"attestation_keys":[{"key_class":"private_key","key_identifier":"att_key_identifier","key_algorithm":"rsa","public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"}]},"version":"2.1"}],"boot_time":"2024-11-12T16:21:17Z"}}}"#);
    }

    #[test]
    fn deserialize_request() {
        // Create a JSON string and deserialize it to an AttestationRequest object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "evidence_supported":[{"evidence_class":"certification",
                                            "evidence_type":"tpm_quote",
                                            "agent_capabilities":{"spec_version":"2.0",
                                            "hash_algorithms":["sha3_512"],
                                            "signing_schemes":["rsassa"],
                                            "attestation_keys":[{"key_class":"private_key","key_identifier":"att_key_identifier",
                                                                "key_algorithm":"rsa",
                                                                "public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"}]},
                                            "version":"2.1"}],
                     "boot_time":"2024-11-12T16:21:17Z"
                }
            }
        }"#;
        let request: AttestationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.data.type_, "attestation");
        assert_eq!(request.data.attributes.evidence_supported[0].evidence_class, "certification");
        assert_eq!(request.data.attributes.evidence_supported[0].version, Some("2.1".to_string()));
        assert_eq!(request.data.attributes.evidence_supported[0].evidence_type, "tpm_quote");
        assert_eq!(request.data.attributes.evidence_supported[0].agent_capabilities.spec_version, "2.0");
        assert_eq!(request.data.attributes.evidence_supported[0].agent_capabilities.hash_algorithms[0], "sha3_512");
        assert_eq!(request.data.attributes.evidence_supported[0].agent_capabilities.signing_schemes[0], "rsassa");
        assert_eq!(request.data.attributes.evidence_supported[0].agent_capabilities.attestation_keys[0].key_class, "private_key");
        assert_eq!(request.data.attributes.evidence_supported[0].agent_capabilities.attestation_keys[0].key_identifier, "att_key_identifier");
        assert_eq!(request.data.attributes.evidence_supported[0].agent_capabilities.attestation_keys[0].key_algorithm, "rsa");
        assert_eq!(request.data.attributes.evidence_supported[0].agent_capabilities.attestation_keys[0].public_hash,
            "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411");
        assert_eq!(request.data.attributes.boot_time, "2024-11-12T16:21:17Z");
    }

    #[test]
    fn serialize_response() {
        // Create a new AttestationResponse object and serialize it to JSON
        let response = AttestationResponse {
            data: ResponseData {
                type_: "attestation".to_string(),
                attributes: ResponseAttributes {
                    evidence_collected: vec![
                        EvidenceCollected {
                            evidence_class: "certification".to_string(),
                            evidence_type: "tpm_quote".to_string(),
                            chosen_parameters: ChosenParameters {
                                nonce: "nonce".to_string(),
                                pcr_selection: vec![0],
                                hash_algorithm: "sha384".to_string(),
                                signing_scheme: "rsassa".to_string(),
                                attestation_key: AttestationKey {
                                    key_class: "private_key".to_string(),
                                    key_identifier: "att_key_identifier".to_string(),
                                    key_algorithm: "rsa".to_string(),
                                    public_hash: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411".to_string(),
                                },
                                starting_offset: Some(25),
                            },
                        },
                    ],
                    boot_time: "2024-11-12T16:21:17Z".to_string(),
                },
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        println!("{}", json);
        assert_eq!(json, r#"{"data":{"type":"attestation","attributes":{"evidence_collected":[{"evidence_class":"certification","evidence_type":"tpm_quote","chosen_parameters":{"nonce":"nonce","pcr_selection":[0],"hash_algorithm":"sha384","signing_scheme":"rsassa","attestation_key":{"key_class":"private_key","key_identifier":"att_key_identifier","key_algorithm":"rsa","public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"},"starting_offset":25}}],"boot_time":"2024-11-12T16:21:17Z"}}}"#);
    }

    #[test]
    fn deserialize_response() {
        // Create a JSON string and deserialize it to an AttestationResponse object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "evidence_collected":[{"evidence_class":"certification",
                                            "evidence_type":"tpm_quote",
                                            "chosen_parameters":{"nonce":"nonce",
                                                                "pcr_selection":[0],
                                                                "hash_algorithm":"sha384",
                                                                "signing_scheme":"rsassa",
                                                                "attestation_key":{"key_class":"private_key",
                                                                                    "key_identifier":"att_key_identifier",
                                                                                    "key_algorithm":"rsa",
                                                                                    "public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"},
                                                                "starting_offset":25}}],
                     "boot_time":"2024-11-12T16:21:17Z"
                }
            }
        }"#;
        let response: AttestationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.type_, "attestation");
        assert_eq!(response.data.attributes.evidence_collected[0].evidence_class, "certification");
        assert_eq!(response.data.attributes.evidence_collected[0].evidence_type, "tpm_quote");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.nonce, "nonce");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.pcr_selection[0], 0);
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.hash_algorithm, "sha384");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.signing_scheme, "rsassa");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.attestation_key.key_class, "private_key");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.attestation_key.key_identifier, "att_key_identifier");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.attestation_key.key_algorithm, "rsa");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.attestation_key.public_hash,
            "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411");
        assert_eq!(response.data.attributes.evidence_collected[0].chosen_parameters.starting_offset, Some(25));
        assert_eq!(response.data.attributes.boot_time, "2024-11-12T16:21:17Z");
    }

}