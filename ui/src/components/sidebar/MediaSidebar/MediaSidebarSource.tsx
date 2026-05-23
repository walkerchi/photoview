import React from 'react'
import { useTranslation } from 'react-i18next'

export type SourceMetadata = {
  __typename: 'MediaSource'
  id: string
  source: string
  url?: string | null
  title?: string | null
  author?: string | null
  authorUrl?: string | null
  caption?: string | null
  tags: string[]
  postDate?: string | null
}

type Props = {
  source?: SourceMetadata | null
}

// Render a single label/value row. Mirrors MediaSidebarExif's row style so
// the panels look like one continuous detail sheet.
const Row = ({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) => (
  <li className="px-1 py-1 flex">
    <span className="w-28 shrink-0 text-xs uppercase text-gray-700 dark:text-gray-300 font-semibold">
      {label}
    </span>
    <span className="flex-1 text-sm break-words">{children}</span>
  </li>
)

const MediaSidebarSource = ({ source }: Props) => {
  const { t } = useTranslation()

  if (!source) return null

  // Hide the section entirely if the only thing we have is the source tag —
  // an empty card just adds noise on a media with no sidecar.
  const hasContent =
    !!source.title ||
    !!source.author ||
    !!source.url ||
    !!source.caption ||
    !!source.postDate ||
    (source.tags && source.tags.length > 0)
  if (!hasContent) return null

  const sourceLabel = t('sidebar.media.source.heading', 'Source')

  return (
    <div className="mx-4 my-4">
      <h2 className="uppercase text-xs text-gray-900 dark:text-gray-300 font-semibold pb-1 border-b border-gray-200 dark:border-dark-border">
        {sourceLabel}
      </h2>
      <ul>
        {source.title && (
          <Row label={t('sidebar.media.source.title', 'Title')}>
            {source.title}
          </Row>
        )}
        {source.author && (
          <Row label={t('sidebar.media.source.author', 'Author')}>
            {source.authorUrl ? (
              <a
                className="text-blue-700 dark:text-blue-300 hover:underline"
                href={source.authorUrl}
                target="_blank"
                rel="noreferrer noopener"
              >
                {source.author}
              </a>
            ) : (
              source.author
            )}
          </Row>
        )}
        {source.url && (
          <Row label={t('sidebar.media.source.url', 'Source')}>
            <a
              className="text-blue-700 dark:text-blue-300 hover:underline break-all"
              href={source.url}
              target="_blank"
              rel="noreferrer noopener"
            >
              {source.source ? `${source.source}: ${source.url}` : source.url}
            </a>
          </Row>
        )}
        {source.postDate && (
          <Row label={t('sidebar.media.source.post_date', 'Posted')}>
            {new Date(source.postDate).toLocaleString()}
          </Row>
        )}
        {source.tags && source.tags.length > 0 && (
          <Row label={t('sidebar.media.source.tags', 'Tags')}>
            <div className="flex flex-wrap gap-1">
              {source.tags.map(tag => (
                <span
                  key={tag}
                  className="inline-block px-2 py-0.5 text-xs rounded bg-gray-200 dark:bg-dark-border text-gray-800 dark:text-gray-200"
                >
                  {tag}
                </span>
              ))}
            </div>
          </Row>
        )}
        {source.caption && (
          <Row label={t('sidebar.media.source.caption', 'Caption')}>
            <p className="whitespace-pre-wrap text-sm">{source.caption}</p>
          </Row>
        )}
      </ul>
    </div>
  )
}

export default MediaSidebarSource
