import React from 'react'
import { gql, useQuery } from '@apollo/client'
import { useTranslation } from 'react-i18next'
import styled from 'styled-components'
import { useIsAdmin } from '../../components/routes/AuthorizedRoute'
import Layout from '../../components/layout/Layout'
import ScannerSection from './ScannerSection'
import UserPreferences from './UserPreferences'
import UsersTable from './Users/UsersTable'
import VersionInfo from './VersionInfo'
import classNames from 'classnames'

const HEADER_AUTH_QUERY = gql`
  query CheckHeaderAuthEnabled {
    siteInfo {
      headerAuthEnabled
    }
  }
`

type SectionTitleProps = {
  children: string
  nospace?: boolean
}

export const SectionTitle = ({ children, nospace }: SectionTitleProps) => {
  return (
    <h2
      className={classNames(
        'pb-1 border-b border-gray-200 dark:border-dark-border text-xl mb-5',
        !nospace && 'mt-6'
      )}
    >
      {children}
    </h2>
  )
}

export const InputLabelTitle = styled.h3.attrs({
  className: 'font-semibold mt-4',
})``

export const InputLabelDescription = styled.p.attrs({
  className: 'text-sm mb-2',
})``

const SettingsPage = () => {
  const { t } = useTranslation()
  const isAdmin = useIsAdmin()
  const { data: ssoData } = useQuery(HEADER_AUTH_QUERY)
  // When SSO owns identity, hide Photoview's user management entirely —
  // creating/editing/deleting users must happen in the SSO provider.
  const ssoMode = ssoData?.siteInfo?.headerAuthEnabled === true

  return (
    <Layout title={t('title.settings', 'Settings')}>
      <UserPreferences />
      {isAdmin && (
        <>
          <ScannerSection />
          {!ssoMode && <UsersTable />}
        </>
      )}
      <VersionInfo />
    </Layout>
  )
}

export default SettingsPage
