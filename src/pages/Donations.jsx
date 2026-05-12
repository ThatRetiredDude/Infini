import { useCallback, useRef, useState } from 'react';

const FUND_URL = 'https://thefund.org';

const CRYPTO_WALLETS = [
  {
    id: 'btc',
    title: 'Bitcoin',
    address: 'bc1qa5kevv33wq5t4sjckqe32h5hcwyymp767tfhz9',
    payUri:
      'bitcoin:bc1qa5kevv33wq5t4sjckqe32h5hcwyymp767tfhz9?label=Infini%20donation',
    blurb: 'Opens your BTC wallet; enter any amount in the app.',
  },
  {
    id: 'doge',
    title: 'Dogecoin',
    address: 'DL13PQpDEGGNxm7jCdBTqq29XDVZyiwYYQ',
    payUri: 'dogecoin:DL13PQpDEGGNxm7jCdBTqq29XDVZyiwYYQ?label=Infini%20donation',
    blurb: 'Opens your Dogecoin wallet if it registers the dogecoin: link.',
  },
  {
    id: 'eth',
    title: 'Ethereum',
    address: '0x5976376b0c2125655e01D0a7758c744c43Fb6D93',
    payUri:
      'ethereum:0x5976376b0c2125655e01D0a7758c744c43Fb6D93@1?label=Infini%20donation',
    blurb: 'Mainnet (chain id 1). Enter amount and gas in your wallet.',
  },
  {
    id: 'sol',
    title: 'Solana',
    address: 'u5zcwMcmrn7qAN4zUJzLhpLDQv81qtFDfZR1ohCrMs9',
    payUri: 'solana:u5zcwMcmrn7qAN4zUJzLhpLDQv81qtFDfZR1ohCrMs9?label=Infini%20donation',
    blurb: 'Solana Pay-style link; wallet support varies—address is copied either way.',
  },
];

export default function Donations() {
  const [copiedId, setCopiedId] = useState(null);
  const copyClearRef = useRef(0);

  const openWallet = useCallback(async (wallet) => {
    window.clearTimeout(copyClearRef.current);
    try {
      await navigator.clipboard.writeText(wallet.address);
      setCopiedId(wallet.id);
      copyClearRef.current = window.setTimeout(() => {
        setCopiedId((prev) => (prev === wallet.id ? null : prev));
      }, 2200);
    } catch {
      setCopiedId(null);
    }
    window.location.href = wallet.payUri;
  }, []);

  return (
    <div className="max-w-3xl mx-auto px-4 py-12">
      <h1 className="text-2xl mb-2">Support Infini</h1>
      <p className="text-ink-300 mb-8">
        Infini is independently developed. Funds keep the repo in development.
        None of it goes to operating costs we don&apos;t need.
      </p>

      <p className="text-sm text-ink-400 mb-4">
        Tap a network below: your address is copied, then your wallet app opens if
        this device has one registered for that link. You choose the amount in the
        app.
      </p>

      <div className="grid gap-4 md:grid-cols-2">
        {CRYPTO_WALLETS.map((w) => (
          <button
            key={w.id}
            type="button"
            className="card p-6 hover:border-accent transition-colors text-left w-full cursor-pointer border-ink-700 bg-ink-900/60"
            onClick={() => openWallet(w)}
          >
            <div className="flex items-start justify-between gap-2 mb-1">
              <h2 className="text-lg text-ink-100">{w.title}</h2>
              {copiedId === w.id ? (
                <span className="text-xs text-accent shrink-0" aria-live="polite">
                  Copied
                </span>
              ) : null}
            </div>
            <p className="text-sm text-ink-400 mb-3">{w.blurb}</p>
            <p className="text-xs font-mono text-ink-500 break-all">{w.address}</p>
          </button>
        ))}

        <a
          href={FUND_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="card p-6 hover:border-accent transition-colors no-underline md:col-span-2"
        >
          <h2 className="text-lg mb-1 text-ink-100">Donate to America&apos;s Fund</h2>
          <p className="text-sm text-ink-400">
            For supporters who prefer giving to thefund.org instead of directly to
            Infini.
          </p>
        </a>
      </div>

      <p className="text-xs text-ink-500 mt-8">
        Thanks for supporting Infini!
      </p>
    </div>
  );
}
