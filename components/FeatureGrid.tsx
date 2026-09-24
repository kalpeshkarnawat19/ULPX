const features = [
  {
    n: "01",
    title: "Secure",
    text: "Sandboxed execution, no arbitrary code, no shell access.",
    tone: "mint",
    icon: "♙",
  },
  {
    n: "02",
    title: "Deterministic",
    text: "Predictable parsing with versioned configurations and strict validation.",
    tone: "blue",
    icon: "◇",
  },
  {
    n: "03",
    title: "Traceable",
    text: "Every field can be traced back to its source with full lineage.",
    tone: "gold",
    icon: "⌁",
  },
  {
    n: "04",
    title: "Validated",
    text: "Parser candidates are tested before certification and promotion.",
    tone: "rose",
    icon: "♢",
  },
  {
    n: "05",
    title: "Air-gap Ready",
    text: "Works in isolated environments with local models and configurations.",
    tone: "mint",
    icon: "≋",
  },
];

export default function FeatureGrid() {
  return (
    <div className="feature-grid">
      {features.map((feature) => (
        <article className="feature-card" key={feature.n}>
          <div className={`feature-icon ${feature.tone}`}>{feature.icon}</div>
          <h3>{feature.title}</h3>
          <p>{feature.text}</p>
          <div className={`feature-line ${feature.tone}`} />
          <span>{feature.n}</span>
        </article>
      ))}
    </div>
  );
}