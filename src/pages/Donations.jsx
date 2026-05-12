const BTCPAY_POS_URL =
  'https://whistlenet.maxwellinternational.ai/apps/mReEzNJk8opMbiMRNyhTydq8SVh/pos';
const FUND_URL = 'https://thefund.org';

export default function Donations() {
  return (
    <div className="max-w-3xl mx-auto px-4 py-12">
      <h1 className="text-2xl mb-2">Support Infini</h1>
      <p className="text-ink-300 mb-8">
        Infini is independently run and self-hosted. Funds keep the blog
        publishing, the security telemetry, and the underlying infrastructure
        humming. None of it goes to operating costs we don&apos;t need.
      </p>

      <div className="grid gap-4 md:grid-cols-2">
        <a
          href={BTCPAY_POS_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="card p-6 hover:border-accent transition-colors no-underline"
        >
          <h2 className="text-lg mb-1 text-ink-100">Donate via WhistleNet</h2>
          <p className="text-sm text-ink-400">
            Self-hosted BTCPay Server POS. Pay with on-chain BTC or Lightning.
            No middlemen, no KYC.
          </p>
        </a>
        <a
          href={FUND_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="card p-6 hover:border-accent transition-colors no-underline"
        >
          <h2 className="text-lg mb-1 text-ink-100">Donate to America&apos;s Fund</h2>
          <p className="text-sm text-ink-400">
            For supporters who prefer giving to thefund.org instead of directly
            to Infini.
          </p>
        </a>
      </div>

      <p className="text-xs text-ink-500 mt-8">
        Operating costs the donations cover: ~$10/mo domain, periodic AI API
        usage for log review, occasional hardware upgrades (currently the
        wishlist is a 4TB NVMe).
      </p>
    </div>
  );
}
