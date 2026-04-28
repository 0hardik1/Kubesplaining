// Package report — kpGraphScript is the inline JavaScript that powers the interactive attack
// graph in the HTML report. It's kept here as a Go const so the report stays self-contained
// (no external assets) and so the JS source remains readable without fighting Go template
// escaping inside the htmlTemplate. The string is injected via template.JS in BuildHTMLData.
//
// Design notes:
//   - Vanilla JS, no library dependencies, runs on DOMContentLoaded.
//   - Reads the GraphPayload from <script type="application/json" id="kp-graph-data">.
//   - Hover / click / keyboard handlers on every <g data-node-id> and <path data-edge-id>.
//   - Side panel ("kp-detail") slides in with glossary + technique + remediation copy.
//   - Filter chips toggle classes on the <svg>; CSS does the actual dimming.
//   - innerHTML is used only for HTML already vetted by Go (Glossary.Long / Techniques.Plain
//     are template.HTML emitted from a hardcoded glossary). All Finding-derived strings (Title,
//     Description, Remediation, References) go through textContent / safe-attribute setters.
package report

const kpGraphScript = `
// --- Tabs / cross-tab helpers (run regardless of graph presence) -----------
(function() {
  var validTabs = { overview: 1, attack: 1, findings: 1 };

  function activate(name) {
    if (!validTabs[name]) name = 'attack';
    document.body.dataset.activeTab = name;
    var btns = document.querySelectorAll('.tab[data-tab]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute('aria-selected', btns[i].getAttribute('data-tab') === name ? 'true' : 'false');
    }
  }

  // Expose for other IIFEs (narrative chip click, chart click → switch tab).
  window.kpActivateTab = activate;

  // Wire tab buttons.
  document.addEventListener('click', function(ev) {
    var btn = ev.target && ev.target.closest && ev.target.closest('.tab[data-tab]');
    if (!btn) return;
    ev.preventDefault();
    activate(btn.getAttribute('data-tab'));
  });

  // ---- Findings filter (driven by chart clicks) ------------------------
  // State is { severity, module, category, resource } — each either a string or null.
  // Clicking a chart row/cell sets the relevant fields, switches to the findings tab,
  // and re-applies the predicate on every <article class="finding">.
  var filterState = { severity: null, module: null, category: null, resource: null };
  var FILTER_KEYS = ['severity', 'module', 'category', 'resource'];
  var FILTER_LABELS = { severity: 'Severity', module: 'Module', category: 'Category', resource: 'Resource' };

  function parseFilterTarget(s) {
    if (!s) return {};
    var out = {};
    s.split('|').forEach(function(part) {
      var p = part.split(':');
      if (p.length === 2) out[p[0]] = p[1];
    });
    return out;
  }

  function applyFindingsFilter() {
    var articles = document.querySelectorAll('article.finding');
    var n = 0;
    for (var i = 0; i < articles.length; i++) {
      var a = articles[i];
      var keep = true;
      for (var k = 0; k < FILTER_KEYS.length; k++) {
        var key = FILTER_KEYS[k];
        var want = filterState[key];
        if (want == null) continue;
        var got = a.getAttribute('data-' + key) || '';
        if (key === 'module') {
          var sec = a.closest('.module-section');
          got = sec ? (sec.getAttribute('data-module') || '') : '';
        }
        if (got !== want) { keep = false; break; }
      }
      a.style.display = keep ? '' : 'none';
      if (keep) n++;
    }
    // Hide module sections whose findings are all filtered out.
    var sections = document.querySelectorAll('section.module-section');
    for (var s = 0; s < sections.length; s++) {
      var visible = sections[s].querySelectorAll('article.finding:not([style*="display: none"])').length;
      sections[s].style.display = visible ? '' : 'none';
    }
    renderFilterChips();
  }

  function renderFilterChips() {
    var bar = document.getElementById('fl-active');
    var clear = document.getElementById('fl-clear');
    if (!bar || !clear) return;
    bar.innerHTML = '';
    var any = false;
    FILTER_KEYS.forEach(function(key) {
      var v = filterState[key];
      if (v == null) return;
      any = true;
      var chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'fl-chip fl-chip-active';
      chip.setAttribute('data-fl-key', key);
      chip.innerHTML = '<span class="fl-chip-key">' + FILTER_LABELS[key] + '</span> <span class="fl-chip-val"></span> <span class="fl-chip-x" aria-hidden="true">×</span>';
      chip.querySelector('.fl-chip-val').textContent = v;
      chip.title = 'Remove ' + FILTER_LABELS[key] + ' filter';
      chip.addEventListener('click', function() {
        filterState[key] = null;
        applyFindingsFilter();
      });
      bar.appendChild(chip);
    });
    bar.hidden = !any;
    clear.hidden = !any;
    var wrap = bar.closest('.findings-filters');
    if (wrap) wrap.hidden = !any;
  }

  // Wire chart row + heatmap cell clicks → set filter, switch to findings tab.
  document.addEventListener('click', function(ev) {
    var t = ev.target && ev.target.closest && ev.target.closest('[data-fl-target]');
    if (!t) return;
    ev.preventDefault();
    var fields = parseFilterTarget(t.getAttribute('data-fl-target'));
    // Reset other fields for clarity — chart clicks set a fresh filter.
    filterState = { severity: null, module: null, category: null, resource: null };
    Object.keys(fields).forEach(function(k) { if (filterState.hasOwnProperty(k)) filterState[k] = fields[k]; });
    activate('findings');
    applyFindingsFilter();
    requestAnimationFrame(function() {
      var nav = document.querySelector('.findings-filters');
      if (nav) nav.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  // Clear-all button.
  document.addEventListener('click', function(ev) {
    if (!ev.target.closest || !ev.target.closest('#fl-clear')) return;
    filterState = { severity: null, module: null, category: null, resource: null };
    applyFindingsFilter();
  });

  // Narrative rule-ID chip → switch to findings tab and scroll the matching finding into view.
  document.addEventListener('click', function(ev) {
    var a = ev.target && ev.target.closest && ev.target.closest('a.chip-link[data-rule]');
    if (!a) return;
    var rule = a.getAttribute('data-rule');
    if (!rule) return;
    var target = document.getElementById('finding-' + rule);
    if (!target) return;
    ev.preventDefault();
    activate('findings');
    requestAnimationFrame(function() {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      target.classList.add('finding-flash');
      setTimeout(function() { target.classList.remove('finding-flash'); }, 1600);
    });
  });

  // Initial activation: parse URL hash. #tab-X selects tab X. #finding-XXX implies findings tab.
  // Default (no hash, unrecognized hash) is the attack-paths tab — the report's primary view.
  function fromHash() {
    var h = (window.location.hash || '').replace(/^#/, '');
    if (!h) return 'attack';
    if (/^tab-(.+)$/.test(h)) return RegExp.$1;
    if (/^finding-/.test(h)) return 'findings';
    var modEl = document.getElementById(h);
    if (modEl && modEl.classList.contains('module-section')) return 'findings';
    return 'attack';
  }

  // Re-scroll to the hash AFTER activation so the target is in the laid-out
  // visible tab; without this, anchor jumps land on a hidden element and end
  // up at a stale y-offset when the correct tab fades in.
  function reanchor() {
    var h = (window.location.hash || '').replace(/^#/, '');
    if (!h) return;
    var el = document.getElementById(h);
    if (el) requestAnimationFrame(function() { el.scrollIntoView({ block: 'start' }); });
  }

  activate(fromHash());
  window.addEventListener('hashchange', function() { activate(fromHash()); reanchor(); });
})();

// --- Attack-graph interactivity (skipped if there's no graph) --------------
(function() {
  var dataEl = document.getElementById('kp-graph-data');
  if (!dataEl) return;
  var payload;
  try { payload = JSON.parse(dataEl.textContent); } catch (e) { return; }
  if (!payload || !payload.Nodes) return;

  var svg = document.querySelector('.attack-svg');
  var panel = document.querySelector('.kp-detail');
  var panelTitle = document.getElementById('kp-detail-title');
  var panelBody = document.getElementById('kp-detail-body');
  var panelClose = panel && panel.querySelector('.kp-detail-close');
  var tooltip = document.querySelector('.kp-tooltip');
  if (!svg || !panel || !tooltip) return;

  var nodeIndex = {};
  (payload.Nodes || []).forEach(function(n) { nodeIndex[n.ID] = n; });
  var edgeIndex = {};
  (payload.Edges || []).forEach(function(e) { edgeIndex[e.ID] = e; });

  var lastFocused = null;
  var walkState = null;

  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function clearHighlights() {
    $$('.kp-hot, .kp-dim', svg).forEach(function(el) {
      el.classList.remove('kp-hot');
      el.classList.remove('kp-dim');
    });
    svg.classList.remove('kp-active');
  }

  function highlightNode(node) {
    if (!node) return;
    svg.classList.add('kp-active');
    var hotIDs = {};
    hotIDs[node.ID] = true;
    (node.EdgeIDs || []).forEach(function(eid) {
      hotIDs[eid] = true;
      var edge = edgeIndex[eid];
      if (!edge) return;
      hotIDs[edge.From] = true;
      hotIDs[edge.To] = true;
    });
    $$('[data-node-id]', svg).forEach(function(el) {
      var id = el.getAttribute('data-node-id');
      if (hotIDs[id]) { el.classList.add('kp-hot'); el.classList.remove('kp-dim'); }
      else { el.classList.add('kp-dim'); el.classList.remove('kp-hot'); }
    });
    $$('[data-edge-id]', svg).forEach(function(el) {
      var id = el.getAttribute('data-edge-id');
      if (hotIDs[id]) { el.classList.add('kp-hot'); el.classList.remove('kp-dim'); }
      else { el.classList.add('kp-dim'); el.classList.remove('kp-hot'); }
    });
  }

  function highlightEdge(edge) {
    if (!edge) return;
    svg.classList.add('kp-active');
    var hotIDs = {};
    hotIDs[edge.ID] = true;
    hotIDs[edge.From] = true;
    hotIDs[edge.To] = true;
    $$('[data-node-id]', svg).forEach(function(el) {
      var id = el.getAttribute('data-node-id');
      if (hotIDs[id]) { el.classList.add('kp-hot'); el.classList.remove('kp-dim'); }
      else { el.classList.add('kp-dim'); el.classList.remove('kp-hot'); }
    });
    $$('[data-edge-id]', svg).forEach(function(el) {
      var id = el.getAttribute('data-edge-id');
      if (hotIDs[id]) { el.classList.add('kp-hot'); el.classList.remove('kp-dim'); }
      else { el.classList.add('kp-dim'); el.classList.remove('kp-hot'); }
    });
  }

  function showTooltip(targetEl, title, htmlBody) {
    var rect = targetEl.getBoundingClientRect();
    tooltip.style.left = (rect.left + window.pageXOffset + Math.min(rect.width / 2, 220)) + 'px';
    tooltip.style.top = (rect.top + window.pageYOffset - 12) + 'px';
    var t = tooltip.querySelector('.kp-tt-title');
    var b = tooltip.querySelector('.kp-tt-body');
    t.textContent = title || '';
    if (htmlBody) { b.innerHTML = htmlBody; b.hidden = false; }
    else { b.innerHTML = ''; b.hidden = true; }
    tooltip.hidden = false;
  }

  function hideTooltip() { tooltip.hidden = true; }

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function(k) {
        if (k === 'class') n.className = attrs[k];
        else if (k === 'html') n.innerHTML = attrs[k];
        else if (k === 'text') n.textContent = attrs[k];
        else if (k === 'attrs') {
          Object.keys(attrs.attrs).forEach(function(ak) { n.setAttribute(ak, attrs.attrs[ak]); });
        } else n.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function(c) {
      if (c == null) return;
      if (typeof c === 'string') n.appendChild(document.createTextNode(c));
      else n.appendChild(c);
    });
    return n;
  }

  function severityLabel(s) {
    switch (s) {
      case 'crit': return 'CRITICAL';
      case 'high': return 'HIGH';
      case 'med': return 'MEDIUM';
      case 'low': return 'LOW';
      default: return (s || '').toUpperCase();
    }
  }

  // renderPanel composes the side-panel content for one node. All Finding-derived strings go
  // through textContent (via the el() helper) so untrusted content never reaches innerHTML.
  // Glossary/technique/category prose is HTML pre-vetted by Go and is allowed via 'html'.
  function renderPanel(node) {
    panelBody.innerHTML = '';
    panelTitle.textContent = node.Title || 'Detail';

    var hd = el('div', { class: 'kp-panel-meta' });
    if (node.Severity) hd.appendChild(el('span', { class: 'kp-sev-badge kp-sev-' + node.Severity, text: severityLabel(node.Severity) }));
    if (node.Kind === 'capability') hd.appendChild(el('span', { class: 'kp-kind-badge', text: 'Abused capability' }));
    else if (node.Kind === 'entry') hd.appendChild(el('span', { class: 'kp-kind-badge', text: 'Entry point' }));
    else if (node.Kind === 'impact') hd.appendChild(el('span', { class: 'kp-kind-badge', text: 'Impact' }));
    if (node.RuleID) hd.appendChild(el('span', { class: 'kp-rule mono', text: node.RuleID }));
    panelBody.appendChild(hd);
    if (node.Subtitle) panelBody.appendChild(el('div', { class: 'kp-panel-sub mono', text: node.Subtitle }));

    var glossary = node.GlossaryKey && payload.Glossary ? payload.Glossary[node.GlossaryKey] : null;
    if (glossary) {
      var sec = el('section', { class: 'kp-section' }, [
        el('h4', { text: 'What is this?' }),
        el('div', { class: 'kp-prose', html: glossary.Long || ('<p>' + (glossary.Short || '') + '</p>') })
      ]);
      if (glossary.DocURL) {
        var doc = el('a', { href: glossary.DocURL, target: '_blank', rel: 'noopener noreferrer', text: 'Kubernetes docs ↗' });
        sec.appendChild(el('div', { class: 'kp-doc-link' }, [doc]));
      }
      panelBody.appendChild(sec);
    }

    var category = node.RiskCategory && payload.Categories ? payload.Categories[node.RiskCategory] : null;
    if (category && node.Kind === 'impact') {
      var csec = el('section', { class: 'kp-section' }, [
        el('h4', { text: 'What this category means' }),
        el('div', { class: 'kp-prose', html: category.Plain || '' })
      ]);
      if (category.Examples && category.Examples.length) {
        var ul = el('ul', { class: 'kp-examples' });
        category.Examples.forEach(function(ex) { ul.appendChild(el('li', { text: ex })); });
        csec.appendChild(ul);
      }
      panelBody.appendChild(csec);
    }

    if (node.Description) {
      panelBody.appendChild(el('section', { class: 'kp-section' }, [
        el('h4', { text: 'Why this finding fires' }),
        el('p', { class: 'kp-prose', text: node.Description })
      ]));
    }

    var techKey = node.TechniqueKey;
    var tech = techKey && payload.Techniques ? payload.Techniques[techKey] : null;
    if (tech) {
      var ts = el('section', { class: 'kp-section kp-tech' }, [
        el('h4', { text: 'What an attacker does: ' + (tech.Title || techKey) }),
        el('div', { class: 'kp-prose', html: tech.Plain || '' })
      ]);
      if (tech.Mitre) ts.appendChild(el('div', { class: 'kp-mitre', text: 'MITRE ATT&CK · ' + tech.Mitre }));
      if (tech.AttackerSteps && tech.AttackerSteps.length) {
        ts.appendChild(el('div', { class: 'kp-steps-hd', text: "What they'd actually run" }));
        tech.AttackerSteps.forEach(function(s) {
          if (s.Cmd) {
            ts.appendChild(makeCmdBlock(s.Cmd, s.Note || ''));
          } else if (s.Note) {
            ts.appendChild(el('p', { class: 'kp-step-note', text: s.Note }));
          }
        });
      }
      panelBody.appendChild(ts);
    }

    if (node.Hops && node.Hops.length) {
      var walkBtn = el('button', { type: 'button', class: 'kp-walk-btn', text: 'Walk the chain step-by-step (' + node.Hops.length + ' hops)' });
      walkBtn.addEventListener('click', function() { startWalkthrough(node); });
      panelBody.appendChild(el('section', { class: 'kp-section' }, [
        el('h4', { text: 'Step-by-step' }),
        el('p', { class: 'kp-prose', text: 'See exactly how a starting identity reaches the target, hop by hop.' }),
        walkBtn
      ]));
    }

    if (node.Remediation) {
      var fixSec = el('section', { class: 'kp-section kp-fix' }, [
        el('h4', { text: 'How to fix' })
      ]);
      var rem = renderRemediation(node.Remediation);
      fixSec.appendChild(rem.prose);
      rem.commands.forEach(function(c) { fixSec.appendChild(makeCmdBlock(c, '')); });
      panelBody.appendChild(fixSec);
    }

    if (node.References && node.References.length) {
      var refsSec = el('section', { class: 'kp-section' }, [el('h4', { text: 'References' })]);
      var refUl = el('ul', { class: 'kp-refs' });
      node.References.forEach(function(href) {
        if (!href) return;
        var safeHref = (typeof href === 'string' && /^https?:/i.test(href)) ? href : '#';
        refUl.appendChild(el('li', {}, [el('a', { href: safeHref, target: '_blank', rel: 'noopener noreferrer', text: href })]));
      });
      refsSec.appendChild(refUl);
      panelBody.appendChild(refsSec);
    }
  }

  function startWalkthrough(node) {
    walkState = { node: node, step: 0 };
    renderWalkStep();
  }

  function renderWalkStep() {
    if (!walkState) return;
    var node = walkState.node;
    var i = walkState.step;
    var hop = node.Hops[i];
    panelBody.innerHTML = '';
    panelTitle.textContent = 'Walkthrough · step ' + (i + 1) + ' of ' + node.Hops.length;

    var nav = el('div', { class: 'kp-walk-nav' });
    var prev = el('button', { type: 'button', class: 'kp-walk-prev', text: '← Prev' });
    var next = el('button', { type: 'button', class: 'kp-walk-next', text: 'Next →' });
    var exit = el('button', { type: 'button', class: 'kp-walk-exit', text: 'Exit walkthrough' });
    if (i === 0) prev.disabled = true;
    if (i === node.Hops.length - 1) next.disabled = true;
    prev.addEventListener('click', function() { if (walkState.step > 0) { walkState.step--; renderWalkStep(); } });
    next.addEventListener('click', function() { if (walkState.step < node.Hops.length - 1) { walkState.step++; renderWalkStep(); } });
    exit.addEventListener('click', function() { walkState = null; renderPanel(node); });
    nav.appendChild(prev); nav.appendChild(next); nav.appendChild(exit);
    panelBody.appendChild(nav);

    panelBody.appendChild(el('div', { class: 'kp-walk-progress', text: 'Step ' + (i + 1) + ' / ' + node.Hops.length + ' · target: ' + (node.Title || '') }));

    var fromBox = el('div', { class: 'kp-walk-card kp-walk-from' }, [
      el('div', { class: 'kp-walk-label', text: 'Starting identity' }),
      el('div', { class: 'kp-walk-id mono', text: hop.From || '(initial subject)' })
    ]);
    var arrow = el('div', { class: 'kp-walk-arrow', text: '↓' });
    var actionBox = el('div', { class: 'kp-walk-card kp-walk-action' }, [
      el('div', { class: 'kp-walk-label', text: 'Technique' }),
      el('div', { class: 'kp-walk-id', text: (hop.Action || '').replace(/_/g, ' ') }),
    ]);
    if (hop.Permission) actionBox.appendChild(el('div', { class: 'kp-walk-perm mono', text: hop.Permission }));
    var tech = hop.TechniqueKey && payload.Techniques ? payload.Techniques[hop.TechniqueKey] : null;
    if (tech) {
      actionBox.appendChild(el('div', { class: 'kp-prose kp-walk-explainer', html: tech.Plain || '' }));
      if (tech.Mitre) actionBox.appendChild(el('div', { class: 'kp-mitre', text: 'MITRE ATT&CK · ' + tech.Mitre }));
    }
    var arrow2 = el('div', { class: 'kp-walk-arrow', text: '↓' });
    var toBox = el('div', { class: 'kp-walk-card kp-walk-to' }, [
      el('div', { class: 'kp-walk-label', text: 'Now controls' }),
      el('div', { class: 'kp-walk-id mono', text: hop.To || '(target)' })
    ]);
    if (hop.Gains) toBox.appendChild(el('div', { class: 'kp-walk-gain', text: hop.Gains }));

    panelBody.appendChild(fromBox);
    panelBody.appendChild(arrow);
    panelBody.appendChild(actionBox);
    panelBody.appendChild(arrow2);
    panelBody.appendChild(toBox);
  }

  function openPanel(node, originEl) {
    walkState = null;
    renderPanel(node);
    panel.hidden = false;
    panel.classList.add('kp-open');
    highlightNode(node);
    if (originEl) lastFocused = originEl;
    if (panelClose) panelClose.focus();
  }

  function closePanel() {
    panel.hidden = true;
    panel.classList.remove('kp-open');
    walkState = null;
    clearHighlights();
    if (lastFocused) { try { lastFocused.focus(); } catch (e) {} }
  }

  // makeCmdBlock builds a copy-able command block. Optional note is a one-line
  // explanation rendered below the command. The Copy button uses delegation
  // (handler attached at panel level below) so it works for dynamically inserted
  // blocks too.
  function makeCmdBlock(commandText, note) {
    var pre = el('pre', {}, [el('code', { text: commandText })]);
    var copy = el('button', { type: 'button', class: 'kp-copy', text: 'Copy' });
    var block = el('div', { class: 'kp-cmd' }, [copy, pre]);
    if (note) block.appendChild(el('p', { class: 'kp-cmd-note', text: note }));
    return block;
  }

  // renderRemediation parses a remediation string. Backtick spans that look
  // like full commands (contain spaces or start with kubectl/kubeadm/helm) are
  // emitted as separate code blocks AFTER the prose; short identifier-style
  // backticks render as inline <code>. Non-backtick text becomes plain text
  // (via textContent — never innerHTML).
  function renderRemediation(text) {
    var prose = el('p', { class: 'kp-prose' });
    var commands = [];
    var re = /` + "`" + `([^` + "`" + `]+)` + "`" + `/g;
    var lastIdx = 0;
    var m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > lastIdx) prose.appendChild(document.createTextNode(text.slice(lastIdx, m.index)));
      var inner = m[1];
      var isCmd = /\s/.test(inner) || /^(kubectl|kubeadm|helm|kubectl-)/.test(inner);
      if (isCmd) {
        commands.push(inner);
        prose.appendChild(el('code', { text: inner }));
      } else {
        prose.appendChild(el('code', { text: inner }));
      }
      lastIdx = m.index + m[0].length;
    }
    if (lastIdx < text.length) prose.appendChild(document.createTextNode(text.slice(lastIdx)));
    return { prose: prose, commands: commands };
  }

  function firstSentence(s, maxLen) {
    if (!s) return '';
    var i = s.indexOf('. ');
    var out = i > 0 ? s.slice(0, i + 1) : s;
    if (out.length > maxLen) out = out.slice(0, maxLen - 1).replace(/\s+\S*$/, '') + '…';
    return out;
  }

  function tooltipBody(node) {
    var lines = [];
    var glossary = node.GlossaryKey && payload.Glossary ? payload.Glossary[node.GlossaryKey] : null;
    if (node.Subtitle) lines.push('<div class="kp-tt-sub">' + escapeHtml(node.Subtitle) + '</div>');
    if (glossary && glossary.Short) lines.push('<div>' + escapeHtml(glossary.Short) + '</div>');
    if (node.Kind === 'capability' && node.Description) {
      lines.push('<div class="kp-tt-why"><span class="kp-tt-tag">Why it matters</span><br>' + escapeHtml(firstSentence(node.Description, 140)) + '</div>');
    }
    if (node.Kind === 'impact') {
      var cat = node.RiskCategory && payload.Categories ? payload.Categories[node.RiskCategory] : null;
      if (cat && cat.Examples && cat.Examples.length) {
        lines.push('<div class="kp-tt-why"><span class="kp-tt-tag">Example</span><br>' + escapeHtml(cat.Examples[0]) + '</div>');
      }
    }
    lines.push('<div class="kp-tt-hint">Click for full explainer →</div>');
    return lines.join('');
  }

  $$('[data-node-id]', svg).forEach(function(g) {
    var id = g.getAttribute('data-node-id');
    var node = nodeIndex[id];
    if (!node) return;
    g.addEventListener('mouseenter', function() {
      highlightNode(node);
      showTooltip(g, node.Title || '', tooltipBody(node));
    });
    g.addEventListener('mouseleave', function() {
      if (!panel.classList.contains('kp-open')) clearHighlights();
      hideTooltip();
    });
    g.addEventListener('click', function() { openPanel(node, g); });
    g.addEventListener('keydown', function(ev) {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openPanel(node, g); }
    });
  });

  $$('[data-edge-id]', svg).forEach(function(p) {
    var id = p.getAttribute('data-edge-id');
    var edge = edgeIndex[id];
    if (!edge) return;
    p.addEventListener('mouseenter', function() {
      highlightEdge(edge);
      var tech = edge.TechniqueKey && payload.Techniques ? payload.Techniques[edge.TechniqueKey] : null;
      var title = (edge.ActionLabel || '');
      var body = tech ? (tech.Title || '') + (tech.Plain ? '<div class="kp-tt-prose">' + tech.Plain + '</div>' : '') : '';
      showTooltip(p, title, body);
    });
    p.addEventListener('mouseleave', function() {
      if (!panel.classList.contains('kp-open')) clearHighlights();
      hideTooltip();
    });
  });

  if (panelClose) panelClose.addEventListener('click', closePanel);
  document.addEventListener('keydown', function(ev) {
    if (ev.key === 'Escape' && panel.classList.contains('kp-open')) closePanel();
  });

  // Delegated copy-button handler for kp-cmd blocks built dynamically inside
  // the panel. Reads the sibling <code> textContent and writes to clipboard,
  // then briefly swaps the button label.
  panel.addEventListener('click', function(ev) {
    var btn = ev.target && ev.target.closest && ev.target.closest('.kp-copy');
    if (!btn) return;
    ev.preventDefault();
    var block = btn.closest('.kp-cmd');
    var code = block && block.querySelector('code');
    if (!code) return;
    var text = code.textContent || '';
    var done = function() {
      var orig = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('kp-copied');
      setTimeout(function() { btn.textContent = orig; btn.classList.remove('kp-copied'); }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function() {
        // Fallback below.
        try {
          var ta = document.createElement('textarea');
          ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta); ta.select(); document.execCommand('copy');
          document.body.removeChild(ta); done();
        } catch (e) { /* clipboard not available */ }
      });
    }
  });

  // Click outside the panel (and outside the graph itself) closes the panel.
  // Clicks on graph nodes don't close — they swap content via openPanel().
  document.addEventListener('mousedown', function(ev) {
    if (!panel.classList.contains('kp-open')) return;
    var t = ev.target;
    if (!t || !t.closest) return;
    if (t.closest('.kp-detail') || t.closest('.attack-svg') || t.closest('.kp-tooltip')) return;
    closePanel();
  });

  // Filter chips: toggle aria-pressed and a class on the SVG for CSS-only dimming.
  $$('.kp-chip', document).forEach(function(chip) {
    chip.addEventListener('click', function() {
      if (chip.getAttribute('data-action') === 'reset') {
        $$('.kp-chip', document).forEach(function(c) {
          if (c.getAttribute('data-action') === 'reset') return;
          c.setAttribute('aria-pressed', 'true');
        });
        applyFilters();
        return;
      }
      var pressed = chip.getAttribute('aria-pressed') === 'true';
      chip.setAttribute('aria-pressed', pressed ? 'false' : 'true');
      applyFilters();
    });
  });

  function applyFilters() {
    var hidden = { sev: {}, kind: {} };
    $$('.kp-chip[data-filter]', document).forEach(function(c) {
      if (c.getAttribute('aria-pressed') === 'false') {
        hidden[c.getAttribute('data-filter')][c.getAttribute('data-value')] = true;
      }
    });
    var classes = svg.className.baseVal.split(/\s+/).filter(function(c) { return !/^kp-hide-/.test(c); });
    Object.keys(hidden.sev).forEach(function(v) { classes.push('kp-hide-sev-' + v); });
    Object.keys(hidden.kind).forEach(function(v) { classes.push('kp-hide-kind-' + v); });
    svg.className.baseVal = classes.filter(Boolean).join(' ');
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
})();
`
