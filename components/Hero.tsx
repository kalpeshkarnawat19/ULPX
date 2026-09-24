"use client";

import dynamic from "next/dynamic";
import { ArrowRight, Download, ShieldCheck } from "lucide-react";

const ULPFXScene = dynamic(() => import("./ULPFXScene"), { ssr: false });

export default function Hero() {
  return (
    <section className="hero" id="home">
      <div className="hero-grid" />

      <div className="hero-copy">
        <div className="eyebrow">
          <span />
          UNIVERSAL LOG PARSING FRAMEWORK
        </div>

        <h1>
          Logs in.
          <br />
          <em>Structure</em> out.
        </h1>

        <p>
          ULPF-X is a lightweight, secure and extensible framework that helps
          you collect, parse and normalize log data — with full traceability
          and control.
        </p>

        <div className="hero-actions">
          <a className="mint-button" href="#download">
            <Download size={17} />
            Download Agent (ZIP)
            <ArrowRight size={16} />
          </a>
          <span>One agent. Every environment.</span>
        </div>
      </div>

      <div className="hero-status">
        <span>Secure&nbsp; →</span>
        <span>Deterministic&nbsp; →</span>
        <span>Air-gap Ready&nbsp; →</span>
      </div>

      <div className="hero-scene" aria-hidden="true">
        <ULPFXScene />
      </div>

      <div className="hero-note">
        <ShieldCheck size={15} />
        <span>Traceability by design</span>
      </div>
    </section>
  );
}