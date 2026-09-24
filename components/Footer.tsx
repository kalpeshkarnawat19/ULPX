import { Github } from "lucide-react";

export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-brand">
        <span className="mini-logo">
          <span />
          <span />
          <span />
        </span>
        <strong>ULPF-X</strong>
        <i />
        <span>Universal Log Parsing Framework</span>
      </div>

      <div className="footer-right">
        <span className="footer-rule" />
        <span>Better logs. Better decisions.</span>
        <a href="https://github.com/" target="_blank" rel="noreferrer" aria-label="GitHub">
          <Github size={18} />
        </a>
      </div>
    </footer>
  );
}