import Hero from "@/components/Hero";
import FeatureGrid from "@/components/FeatureGrid";
import Footer from "@/components/Footer";
import { ArrowUpRight, BookOpen, Github, ShieldCheck } from "lucide-react";

export default function Home() {
  return (
    <main>
      <header className="site-header">
        <a className="brand" href="#home" aria-label="ULPF-X home">
          <span className="brand-mark">
            <span />
            <span />
            <span />
          </span>
          <span>ULPF-X</span>
        </a>

        <nav className="nav" aria-label="Primary navigation">
          <a className="active" href="#home">Home</a>
          <a href="#download">Download</a>
          <a href="#documentation">Documentation</a>
          <a href="#about">About</a>
        </nav>

        <div className="header-actions">
          <a
            className="icon-link"
            href="https://github.com/"
            target="_blank"
            rel="noreferrer"
            aria-label="GitHub"
          >
            <Github size={19} strokeWidth={1.7} />
          </a>
          <span className="header-divider" />
        </div>
      </header>

      <Hero />

      <section className="support-strip" id="download">
        <div className="support-label">
          <span>SUPPORTED ON</span>
          <i />
        </div>

        <div className="platforms">
          {["Linux", "Windows", "macOS", "Docker", "Kubernetes"].map((item) => (
            <div className="platform" key={item}>
              <div className="platform-icon">
                {item === "Linux" && "◈"}
                {item === "Windows" && "⊞"}
                {item === "macOS" && "●"}
                {item === "Docker" && "⬡"}
                {item === "Kubernetes" && "✥"}
              </div>
              <span>{item}</span>
            </div>
          ))}
        </div>

        <div className="agent-card">
          <span className="mini-logo">
            <span />
            <span />
            <span />
          </span>
          <div>
            <strong>ULPF-X Agent v1.0.0</strong>
            <small>A single, universal package with everything you need.</small>
          </div>
          <a className="mint-button compact" href="#documentation">
            Download Agent <ArrowUpRight size={16} />
          </a>
        </div>
      </section>

      <section className="why section" id="about">
        <div className="why-copy">
          <div className="eyebrow">
            <span />
            WHY ULPF-X
            <i />
          </div>
          <h2>
            Built for <br />
            <em>uncertain</em> data.
          </h2>
          <p>
            From unknown logs to trusted telemetry — ULPF-X gives you control,
            visibility and security at every step.
          </p>
        </div>

        <FeatureGrid />
      </section>

      <section className="architecture section" id="documentation">
        <div className="section-heading">
          <div className="eyebrow"><span /> PIPELINE <i /></div>
          <h2>One path from raw logs to <em>trusted telemetry.</em></h2>
          <p>
            Every transition is explicit, validated and traceable. The same
            visual model maps directly to the framework architecture.
          </p>
        </div>

        <div className="pipeline">
          {[
            ["01", "Raw logs", "syslog · json · cef", "input"],
            ["02", "Parser", "DSL / rules", "parser"],
            ["03", "ULPF-IR", "normalized events", "ir"],
            ["04", "Lineage", "traceable fields", "lineage"],
            ["05", "Validation", "certified parser", "validation"],
            ["06", "Export", "SIEM / storage / lake", "export"],
          ].map(([n, title, desc, type]) => (
            <div className="pipeline-node" data-type={type} key={n}>
              <span>{n}</span>
              <div>
                <strong>{title}</strong>
                <small>{desc}</small>
              </div>
              {n !== "06" && <b>→</b>}
            </div>
          ))}
        </div>
      </section>

      <section className="docs-callout section">
        <div>
          <div className="eyebrow"><span /> DOCUMENTATION <i /></div>
          <h2>Designed to be inspected.</h2>
          <p>
            Contracts, parser candidates, validation results and lineage are
            first-class artifacts — not hidden implementation details.
          </p>
        </div>
        <div className="docs-actions">
          <a className="outline-button" href="#documentation">
            <BookOpen size={17} /> Read documentation
          </a>
          <a className="outline-button" href="https://github.com/" target="_blank" rel="noreferrer">
            <Github size={17} /> View repository
          </a>
        </div>
      </section>

      <Footer />
    </main>
  );
}