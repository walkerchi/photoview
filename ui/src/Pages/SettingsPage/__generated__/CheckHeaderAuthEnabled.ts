/* tslint:disable */
/* eslint-disable */
// @generated
// This file was automatically generated and should not be edited.

// ====================================================
// GraphQL query operation: CheckHeaderAuthEnabled
// ====================================================

export interface CheckHeaderAuthEnabled_siteInfo {
  __typename: "SiteInfo";
  /**
   * Whether reverse-proxy header authentication is enabled — when true, the UI should hide its own login and user-management views because identity is owned by the proxy
   */
  headerAuthEnabled: boolean;
}

export interface CheckHeaderAuthEnabled {
  siteInfo: CheckHeaderAuthEnabled_siteInfo;
}
