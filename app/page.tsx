import Hero from "@/components/Hero";
import FeatureGrid from "@/components/FeatureGrid";
import Footer from "@/components/Footer";
import {
  ArrowUpRight,
  BookOpen,
  Github,
  Terminal,
  Download,
} from "lucide-react";

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
          <a className="active" href="#home">
            Home
          </a>
          <a href="#download">Download</a>
          <a href="#installation">Installation</a>
          <a href="#documentation">Documentation</a>
          <a href="#about">About</a>
        </nav>

        <div className="header-actions">
          <a
            className="icon-link"
            href="https://github.com/kalpeshkarnawat19/ULPX"
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

      {/* DOWNLOAD / SUPPORTED PLATFORMS */}
      <section className="support-strip" id="download">
        <div className="support-label">
          <span>SUPPORTED ON</span>
          <i />
        </div>

        <div className="platforms">
          {["Linux", "Windows", "macOS", "Docker", "Kubernetes"].map(
            (item) => (
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
            )
          )}
        </div>

        <div className="agent-card">
          <span className="mini-logo">
            <span />
            <span />
            <span />
          </span>

          <div>
            <strong>ULPF-X Agent v1.0.0</strong>
            <small>
              A single, universal package with everything you need.
            </small>
          </div>

          <a className="mint-button compact" href="#installation">
            Download Agent <ArrowUpRight size={16} />
          </a>
        </div>
      </section>

      {/* INSTALLATION GUIDE */}
      <section className="installation section" id="installation">
        <div className="section-heading">
          <div className="eyebrow">
            <span /> INSTALLATION <i />
          </div>

          <h2>
            Get ULPF-X running <em>in minutes.</em>
          </h2>

          <p>
            Download and extract{" "}
            <code>ULPF-X-Standalone-v1.0.0.zip</code>, open your terminal in
            the extracted folder, and run the command for your operating
            system.
          </p>
        </div>

        <div className="installation-grid">
          {/* WINDOWS — CMD / DOUBLE CLICK */}
          <div className="installation-card">
            <div className="installation-card-top">
              <div>
                <span className="installation-number">01</span>
                <strong>Windows</strong>
              </div>

              <span className="installation-shell">
                Command Prompt / Double-Click
              </span>
            </div>

            <div className="installation-command">
              <div className="command-label">
                <Terminal size={16} />
                COMMAND
              </div>

              <code>
                Double-click <b>install.bat</b>
              </code>

              <span className="command-or">or run</span>

              <code>.\install.bat</code>
            </div>
          </div>

          {/* WINDOWS — POWERSHELL */}
          <div className="installation-card">
            <div className="installation-card-top">
              <div>
                <span className="installation-number">02</span>
                <strong>Windows</strong>
              </div>

              <span className="installation-shell">PowerShell</span>
            </div>

            <div className="installation-command">
              <div className="command-label">
                <Terminal size={16} />
                COMMAND
              </div>

              <code>
                powershell -ExecutionPolicy Bypass -File
                .\scripts\install.ps1
              </code>
            </div>
          </div>

          {/* macOS */}
          <div className="installation-card">
            <div className="installation-card-top">
              <div>
                <span className="installation-number">03</span>
                <strong>macOS</strong>
              </div>

              <span className="installation-shell">
                Terminal (Zsh / Bash)
              </span>
            </div>

            <div className="installation-command">
              <div className="command-label">
                <Terminal size={16} />
                COMMAND
              </div>

              <code>bash install.sh</code>
            </div>
          </div>

          {/* Linux */}
          <div className="installation-card">
            <div className="installation-card-top">
              <div>
                <span className="installation-number">04</span>
                <strong>Linux</strong>
              </div>

              <span className="installation-shell">
                Terminal (Bash / Zsh)
              </span>
            </div>

            <div className="installation-command">
              <div className="command-label">
                <Terminal size={16} />
                COMMAND
              </div>

              <code>bash install.sh</code>
            </div>
          </div>
        </div>

        <div className="installation-note">
          <Download size={17} />
          <span>
            The standalone package contains the files required to install and
            run ULPF-X locally.
          </span>
        </div>
      </section>

      {/* WHY ULPF-X */}
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

      {/* PIPELINE */}
      <section className="architecture section" id="documentation">
        <div className="section-heading">
          <div className="eyebrow">
            <span /> PIPELINE <i />
          </div>

          <h2>
            One path from raw logs to <em>trusted telemetry.</em>
          </h2>

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

      {/* DOCUMENTATION */}
      <section className="docs-callout section">
        <div>
          <div className="eyebrow">
            <span /> DOCUMENTATION <i />
          </div>

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

          <a
            className="outline-button"
            href="https://github.com/kalpeshkarnawat19/ULPX"
            target="_blank"
            rel="noreferrer"
          >
            <Github size={17} /> View repository
          </a>
        </div>
      </section>

      <Footer />
    </main>
  );
}