import { Cpu, ShieldCheck, ClipboardCheck } from "lucide-react";
import type { CopyApi } from "../lib/copy";
import { GeneratorPanel } from "./GeneratorPanel";

export default function GeneratorView({ onCopy }: { onCopy: CopyApi["copyText"] }) {
  return (
    <section className="panel-page" aria-label="Password generator">
      <header className="panel-head">
        <span className="eyebrow">Tools</span>
        <h1 className="panel-title">Generator</h1>
        <p className="panel-sub">
          Every value below was drawn by the Rust core with its own CSPRNG. The
          renderer receives the string and nothing else.
        </p>
      </header>

      <div className="panel-scroll">
        <div className="panel-column">
          <section className="card generator-card">
            <GeneratorPanel variant="standalone" onCopy={onCopy} />
          </section>

          <section className="card">
            <div className="card-head">
              <h2 className="card-title">How this is made</h2>
            </div>
            <ul className="fact-list">
              <li>
                <Cpu size={14} aria-hidden />
                <span>
                  <code>generate_password</code> runs in the core, not in
                  JavaScript. At least one character comes from every enabled
                  set; the output is shuffled afterwards.
                </span>
              </li>
              <li>
                <ShieldCheck size={14} aria-hidden />
                <span>
                  Length is clamped to 8–128 in Rust. This page asks for 8–64,
                  the range a person can actually paste into a form.
                </span>
              </li>
              <li>
                <ClipboardCheck size={14} aria-hidden />
                <span>
                  Copying uses the same core path as an item field, so the
                  clipboard wipe timer starts immediately.
                </span>
              </li>
            </ul>
            <p className="gen-note">
              Entropy is shown as an estimate of the generator's alphabet and
              length, not as a measurement of the produced string.
            </p>
          </section>
        </div>
      </div>
    </section>
  );
}
