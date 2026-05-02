
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
  // State is { severity, module, category, resource } — each either a string or null,
  // plus a free-text searchQuery (already lowercased). Clicking a chart row/cell sets
  // the relevant fields, switches to the findings tab, and re-applies the predicate on
  // every .finding[data-rule] instance. State changes flow through commitFilters() which
  // also persists to location.hash so a filtered view is shareable.
  var filterState = { severity: null, module: null, category: null, resource: null };
  var searchQuery = '';
  var FILTER_KEYS = ['severity', 'module', 'category', 'resource'];
  var FILTER_LABELS = { severity: 'Severity', module: 'Module', category: 'Category', resource: 'Resource' };
  var suppressHashWrite = false; // set during programmatic restore so we don't loop hashchange→write→hashchange

  function parseFilterTarget(s) {
    if (!s) return {};
    var out = {};
    s.split('|').forEach(function(part) {
      var p = part.split(':');
      if (p.length === 2) out[p[0]] = p[1];
    });
    return out;
  }

  // matchesSearch builds a lowercase haystack lazily for each instance and caches it on
  // the element. The report is static — instances don't move, attributes don't change —
  // so the cache is safe for the page's lifetime.
  function matchesSearch(el, q) {
    if (!q) return true;
    if (el.__searchHay == null) {
      var parts = [
        el.getAttribute('data-rule') || '',
        el.getAttribute('data-subject') || '',
        el.getAttribute('data-resource') || '',
        el.getAttribute('data-category') || ''
      ];
      var titleEl = el.querySelector('.instance-title');
      if (titleEl) parts.push(titleEl.textContent || '');
      var ruleCard = el.closest('.rule-group');
      if (ruleCard) {
        var ruleTitleEl = ruleCard.querySelector('.rule-title');
        if (ruleTitleEl) parts.push(ruleTitleEl.textContent || '');
      }
      el.__searchHay = parts.join(' ').toLowerCase();
    }
    return el.__searchHay.indexOf(q) !== -1;
  }

  function applyFindingsFilter() {
    // Findings are rendered as per-subject .finding instances inside .rule-group cards.
    // Filter at instance granularity, then roll the visibility up to rule groups and module
    // sections so empty containers collapse cleanly.
    var instances = document.querySelectorAll('.finding[data-rule]');
    // When any filter narrows the result set, auto-open matching <details> instances so
    // the user lands on relevant evidence without an extra click.
    var anyFilter = !!searchQuery;
    if (!anyFilter) {
      for (var fk = 0; fk < FILTER_KEYS.length; fk++) {
        if (filterState[FILTER_KEYS[fk]] != null) { anyFilter = true; break; }
      }
    }
    var n = 0;
    for (var i = 0; i < instances.length; i++) {
      var a = instances[i];
      var keep = matchesSearch(a, searchQuery);
      if (keep) {
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
      }
      a.style.display = keep ? '' : 'none';
      if (keep) {
        n++;
        if (anyFilter && a.tagName === 'DETAILS') a.open = true;
      }
    }
    // Hide rule-group cards whose instances are all filtered out.
    var groups = document.querySelectorAll('.rule-group');
    for (var g = 0; g < groups.length; g++) {
      var visibleInGroup = groups[g].querySelectorAll('.finding[data-rule]:not([style*="display: none"])').length;
      groups[g].style.display = visibleInGroup ? '' : 'none';
    }
    // Hide module sections whose rule-groups are all filtered out.
    var sections = document.querySelectorAll('section.module-section');
    for (var s = 0; s < sections.length; s++) {
      var visibleSec = sections[s].querySelectorAll('.rule-group:not([style*="display: none"])').length;
      sections[s].style.display = visibleSec ? '' : 'none';
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
        commitFilters();
      });
      bar.appendChild(chip);
    });
    bar.hidden = !any;
    clear.hidden = !any;
    var wrap = bar.closest('.findings-filters');
    if (wrap) wrap.hidden = !any;
  }

  // commitFilters re-applies the predicate AND mirrors the current filter+search state
  // into location.hash so a filtered view is shareable. Skip the hash write when we're
  // restoring state from the hash itself (avoids feedback loops on hashchange).
  function commitFilters() {
    applyFindingsFilter();
    if (!suppressHashWrite) writeHash();
  }

  // Hash format: <anchor>?<params>
  //   anchor   — existing semantics (#tab-X, #finding-X, #module-id, or empty)
  //   params   — &-separated key=value: q (search), severity, module, category, resource
  // Examples:
  //   #findings?q=cluster-admin&severity=crit
  //   #finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN?severity=crit
  function parseHash() {
    var raw = (window.location.hash || '').replace(/^#/, '');
    var qpos = raw.indexOf('?');
    var anchor = qpos >= 0 ? raw.slice(0, qpos) : raw;
    var query = qpos >= 0 ? raw.slice(qpos + 1) : '';
    var params = {};
    if (query) {
      query.split('&').forEach(function(pair) {
        if (!pair) return;
        var eq = pair.indexOf('=');
        if (eq < 0) return;
        var k = decodeURIComponent(pair.slice(0, eq));
        var v = decodeURIComponent(pair.slice(eq + 1));
        if (k) params[k] = v;
      });
    }
    return { anchor: anchor, params: params };
  }

  function writeHash() {
    var current = parseHash();
    var parts = [];
    if (searchQuery) parts.push('q=' + encodeURIComponent(searchQuery));
    FILTER_KEYS.forEach(function(k) {
      if (filterState[k] != null) parts.push(k + '=' + encodeURIComponent(filterState[k]));
    });
    var anchor = current.anchor;
    // When filters/search are present and there's no existing anchor, default to the findings
    // tab so a refresh lands on the right view. When filters/search are cleared, drop the
    // query entirely but keep any existing anchor (#tab-X / #finding-Y / module id).
    var newHash;
    if (parts.length === 0) {
      newHash = anchor ? '#' + anchor : '';
    } else {
      newHash = '#' + (anchor || 'findings') + '?' + parts.join('&');
    }
    if (newHash === window.location.hash) return;
    if (newHash === '' && !window.location.hash) return;
    // Use replaceState rather than location.hash assignment so we don't pollute the back stack
    // on every keystroke / chip toggle.
    try {
      history.replaceState(null, '', newHash || window.location.pathname + window.location.search);
    } catch (_) {
      // file:// URLs in some browsers reject replaceState — fall back gracefully.
      window.location.hash = newHash;
    }
  }

  // applyHashState restores filterState + searchQuery + the search input value from the
  // URL hash. Called on initial load and on hashchange. suppressHashWrite blocks the
  // commit cascade from re-writing the hash and looping.
  function applyHashState() {
    var p = parseHash();
    var nextFilter = { severity: null, module: null, category: null, resource: null };
    FILTER_KEYS.forEach(function(k) { if (p.params[k] != null) nextFilter[k] = p.params[k]; });
    var nextQuery = p.params.q != null ? String(p.params.q).toLowerCase() : '';
    filterState = nextFilter;
    searchQuery = nextQuery;
    var input = document.getElementById('findings-search-input');
    if (input) input.value = p.params.q != null ? p.params.q : '';
    suppressHashWrite = true;
    try { applyFindingsFilter(); } finally { suppressHashWrite = false; }
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
    commitFilters();
    requestAnimationFrame(function() {
      var nav = document.querySelector('.findings-filters');
      if (nav) nav.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  // Clear-all button — also clears the search input so the URL hash drops back to bare.
  document.addEventListener('click', function(ev) {
    if (!ev.target.closest || !ev.target.closest('#fl-clear')) return;
    filterState = { severity: null, module: null, category: null, resource: null };
    searchQuery = '';
    var input = document.getElementById('findings-search-input');
    if (input) input.value = '';
    commitFilters();
  });

  // Findings search input — debounced free-text filter on the rendered cards.
  // "/" focuses from anywhere outside form fields; Esc clears + blurs.
  function initFindingsSearch() {
    var input = document.getElementById('findings-search-input');
    if (!input) return;
    var debounce;
    input.addEventListener('input', function() {
      clearTimeout(debounce);
      debounce = setTimeout(function() {
        searchQuery = (input.value || '').trim().toLowerCase();
        commitFilters();
      }, 80);
    });
    input.addEventListener('keydown', function(ev) {
      if (ev.key === 'Escape') {
        if (input.value) {
          input.value = '';
          searchQuery = '';
          commitFilters();
        } else {
          input.blur();
        }
        ev.preventDefault();
      }
    });
    document.addEventListener('keydown', function(ev) {
      if (ev.key !== '/') return;
      var t = ev.target;
      if (!t) return;
      var tag = (t.tagName || '').toUpperCase();
      if (tag === 'INPUT' || tag === 'TEXTAREA' || t.isContentEditable === true) return;
      ev.preventDefault();
      input.focus();
      input.select();
    });
  }
  initFindingsSearch();

  // Module-nav scroll-spy: highlight the .module-link whose .module-section is currently
  // crossing the viewport. rootMargin offsets account for the sticky topbar (~80px) at the
  // top and discount the lower half of the viewport so a "section is active" only when it's
  // actually being read. Most-overlapping section wins when multiple are partially visible.
  function initModuleScrollSpy() {
    var nav = document.querySelector('.modules-nav');
    if (!nav) return;
    var sections = document.querySelectorAll('.module-section[id]');
    if (!sections.length) return;
    if (typeof IntersectionObserver === 'undefined') return; // gracefully no-op on legacy browsers
    var linksByID = {};
    nav.querySelectorAll('a.module-link').forEach(function(a) {
      var href = a.getAttribute('href') || '';
      if (href.charAt(0) === '#') linksByID[href.slice(1)] = a;
    });
    var visible = {};
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) visible[e.target.id] = e.intersectionRatio;
        else delete visible[e.target.id];
      });
      // Pick the section with the largest currently-visible ratio; clear the rest.
      var best = null, bestRatio = 0;
      Object.keys(visible).forEach(function(id) {
        if (visible[id] > bestRatio) { bestRatio = visible[id]; best = id; }
      });
      Object.keys(linksByID).forEach(function(id) {
        if (id === best) linksByID[id].classList.add('active');
        else linksByID[id].classList.remove('active');
      });
    }, { rootMargin: '-120px 0px -50% 0px', threshold: [0, 0.25, 0.5, 0.75, 1] });
    sections.forEach(function(s) { observer.observe(s); });
  }
  initModuleScrollSpy();

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
  // Hash with ?params (filters/search) implies findings tab when no other anchor was given.
  // Default (no hash, unrecognized hash) is the attack-paths tab — the report's primary view.
  function fromHash() {
    var p = parseHash();
    var h = p.anchor;
    if (!h) {
      // No anchor but params present (e.g. "#?q=...") → findings tab.
      if (Object.keys(p.params).length > 0) return 'findings';
      return 'attack';
    }
    if (/^tab-(.+)$/.test(h)) return RegExp.$1;
    if (h === 'findings') return 'findings';
    if (/^finding-/.test(h)) return 'findings';
    var modEl = document.getElementById(h);
    if (modEl && modEl.classList.contains('module-section')) return 'findings';
    return 'attack';
  }

  // Re-scroll to the hash AFTER activation so the target is in the laid-out
  // visible tab; without this, anchor jumps land on a hidden element and end
  // up at a stale y-offset when the correct tab fades in.
  function reanchor() {
    var p = parseHash();
    if (!p.anchor) return;
    var el = document.getElementById(p.anchor);
    if (el) requestAnimationFrame(function() { el.scrollIntoView({ block: 'start' }); });
  }

  activate(fromHash());
  applyHashState();
  window.addEventListener('hashchange', function() {
    activate(fromHash());
    applyHashState();
    reanchor();
  });
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
  // navStack remembers the entry node when the user drilled into a capability via
  // the entry panel's path cards, so the cap panel can render a "← Back to {entry}"
  // link. Cleared on direct SVG node clicks and on closePanel so a stale entry never
  // leaks across sessions.
  var navStack = null;
  var backdrop = document.querySelector('.kp-backdrop');

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
    // Title may contain backticks/**bold** from analyzer-supplied finding text;
    // renderInlineHTML escapes content and inserts safe <code>/<strong> tags.
    t.innerHTML = renderInlineHTML(title || '');
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

  // ---- Markdown helpers (popup-pane prose) -----------------------------
  // Tiny tokenizer for the limited markdown analyzers emit:
  //   `code`         → <code>
  //   **bold** → <strong>
  // Always uses textContent for content so analyzer strings can never
  // inject HTML. Returns nothing — appends nodes into the target.
  function renderInline(text, target) {
    var s = String(text || '');
    var i = 0;
    while (i < s.length) {
      var bold = s.indexOf('**', i);
      var code = s.indexOf('`', i);
      var next = -1, which = null;
      if (bold >= 0 && (code < 0 || bold < code)) { next = bold; which = 'bold'; }
      else if (code >= 0) { next = code; which = 'code'; }
      if (next < 0) {
        target.appendChild(document.createTextNode(s.slice(i)));
        return;
      }
      if (next > i) target.appendChild(document.createTextNode(s.slice(i, next)));
      if (which === 'bold') {
        var end = s.indexOf('**', next + 2);
        if (end < 0) { target.appendChild(document.createTextNode(s.slice(next))); return; }
        var strong = document.createElement('strong');
        strong.textContent = s.slice(next + 2, end);
        target.appendChild(strong);
        i = end + 2;
      } else {
        var endC = s.indexOf('`', next + 1);
        if (endC < 0) { target.appendChild(document.createTextNode(s.slice(next))); return; }
        var c = document.createElement('code');
        c.textContent = s.slice(next + 1, endC);
        target.appendChild(c);
        i = endC + 1;
      }
    }
  }

  // renderInlineHTML mirrors renderInline but returns an HTML string instead of
  // appending DOM nodes — the floating tooltip uses innerHTML so it needs an
  // HTML-string output. Text content is always escaped; only the safe `<code>`
  // and `<strong>` tags are inserted.
  function renderInlineHTML(text) {
    var s = String(text || '');
    var out = '';
    var i = 0;
    while (i < s.length) {
      var bold = s.indexOf('**', i);
      var code = s.indexOf('`', i);
      var next = -1, which = null;
      if (bold >= 0 && (code < 0 || bold < code)) { next = bold; which = 'bold'; }
      else if (code >= 0) { next = code; which = 'code'; }
      if (next < 0) { out += escapeHtml(s.slice(i)); break; }
      if (next > i) out += escapeHtml(s.slice(i, next));
      if (which === 'bold') {
        var end = s.indexOf('**', next + 2);
        if (end < 0) { out += escapeHtml(s.slice(next)); break; }
        out += '<strong>' + escapeHtml(s.slice(next + 2, end)) + '</strong>';
        i = end + 2;
      } else {
        var endC = s.indexOf('`', next + 1);
        if (endC < 0) { out += escapeHtml(s.slice(next)); break; }
        out += '<code>' + escapeHtml(s.slice(next + 1, endC)) + '</code>';
        i = endC + 1;
      }
    }
    return out;
  }

  // renderMarkdownBlocks splits text into block-level chunks: paragraphs (\n\n
  // separated), bullet lists (lines all starting with "- " or "* "), and
  // numbered lists (lines all starting with "N. "). Each block is appended to
  // container; inline markdown inside is handled by renderInline.
  function renderMarkdownBlocks(text, container) {
    var t = String(text || '').replace(/\r\n/g, '\n').trim();
    if (!t) return;
    t.split(/\n\n+/).forEach(function(para) {
      para = para.replace(/^\n+|\n+$/g, '');
      if (!para) return;
      var lines = para.split('\n');
      var nonEmpty = lines.filter(function(l) { return l.trim().length > 0; });
      var allBullets = nonEmpty.length > 0 && nonEmpty.every(function(l) { return /^\s*[-*]\s+/.test(l); });
      var allNum = nonEmpty.length > 0 && nonEmpty.every(function(l) { return /^\s*\d+\.\s+/.test(l); });
      if (allBullets && nonEmpty.length >= 1) {
        var ul = document.createElement('ul');
        nonEmpty.forEach(function(l) {
          var li = document.createElement('li');
          renderInline(l.replace(/^\s*[-*]\s+/, ''), li);
          ul.appendChild(li);
        });
        container.appendChild(ul);
      } else if (allNum && nonEmpty.length >= 1) {
        var ol = document.createElement('ol');
        nonEmpty.forEach(function(l) {
          var li = document.createElement('li');
          renderInline(l.replace(/^\s*\d+\.\s+/, ''), li);
          ol.appendChild(li);
        });
        container.appendChild(ol);
      } else {
        var p = document.createElement('p');
        lines.forEach(function(l, idx) {
          if (idx > 0) p.appendChild(document.createElement('br'));
          renderInline(l, p);
        });
        container.appendChild(p);
      }
    });
  }

  // impactForCap walks a capability node's outgoing edge to find the impact node it
  // leads to. Capabilities have exactly one outgoing edge (cap → impact) per the
  // build in attack_graph.go, so a linear scan over EdgeIDs is correct and cheap.
  function impactForCap(capNode) {
    var ids = (capNode && capNode.EdgeIDs) || [];
    for (var i = 0; i < ids.length; i++) {
      var e = edgeIndex[ids[i]];
      if (e && e.From === capNode.ID) {
        var dest = nodeIndex[e.To];
        if (dest && dest.Kind === 'impact') return dest;
      }
    }
    return null;
  }

  // renderEntryPaths builds the "N attack paths from here" section for an entry node.
  // It walks the entry's outgoing edges to find each connected capability, sorts them
  // by severity so the worst paths surface first, and renders one tappable card per
  // capability. Tapping a card calls openPanel(cap, …, { fromEntry: entry }) which
  // sets navStack so the cap panel can show a "← Back to {entry}" affordance.
  // Returns null when the entry has no connected capabilities (defensive — should not
  // happen in practice since entries only exist because they spawned at least one cap).
  function renderEntryPaths(entry) {
    var ids = (entry && entry.EdgeIDs) || [];
    var caps = [];
    for (var i = 0; i < ids.length; i++) {
      var e = edgeIndex[ids[i]];
      if (!e || e.From !== entry.ID) continue;
      var cap = nodeIndex[e.To];
      if (cap && cap.Kind === 'capability') caps.push({ cap: cap, edge: e });
    }
    if (!caps.length) return null;
    var rank = { crit: 0, high: 1, med: 2, low: 3 };
    caps.sort(function(a, b) {
      var ra = rank[a.cap.Severity] != null ? rank[a.cap.Severity] : 9;
      var rb = rank[b.cap.Severity] != null ? rank[b.cap.Severity] : 9;
      return ra - rb;
    });

    var heading = caps.length === 1 ? '1 attack path from here' : caps.length + ' attack paths from here';
    var sec = el('section', { class: 'kp-section kp-paths-section' }, [
      el('h4', { text: heading }),
      el('p', { class: 'kp-paths-hint', text: 'Each card is one way an attacker abuses this entry point. Tap to walk through the technique step-by-step.' })
    ]);
    caps.forEach(function(it) {
      var cap = it.cap;
      var impact = impactForCap(cap);
      var sev = cap.Severity || 'med';
      var card = el('button', { type: 'button', class: 'kp-path-card kp-path-card-' + sev, attrs: { 'aria-label': 'Open attack path: ' + (cap.Title || '') } });
      var hd = el('div', { class: 'kp-path-card-hd' });
      hd.appendChild(el('span', { class: 'kp-sev-badge kp-sev-' + sev, text: severityLabel(sev) }));
      if (cap.RuleID) hd.appendChild(el('span', { class: 'kp-rule mono', text: cap.RuleID }));
      card.appendChild(hd);
      var titleEl = el('div', { class: 'kp-path-card-title' });
      renderInline(cap.Title || '', titleEl);
      card.appendChild(titleEl);
      var meta = el('div', { class: 'kp-path-card-meta' });
      if (impact && impact.Title) {
        meta.appendChild(el('span', { class: 'kp-path-arrow', text: '→' }));
        meta.appendChild(el('span', { class: 'kp-path-impact', text: impact.Title }));
      }
      if (cap.Hops && cap.Hops.length) {
        var hopText = cap.Hops.length + '-step chain';
        meta.appendChild(el('span', { class: 'kp-path-hops', text: hopText }));
      }
      if (meta.firstChild) card.appendChild(meta);
      var cta = el('span', { class: 'kp-path-cta', text: 'Walk the path →' });
      card.appendChild(cta);
      card.addEventListener('click', function() {
        openPanel(cap, card, { fromEntry: entry });
      });
      sec.appendChild(card);
    });
    return sec;
  }

  // renderBackLink prepends a "← Back to {entry}" button to the panel body when the
  // user drilled into the current capability via an entry path-card. Idempotent —
  // safely callable on every renderPanel pass; only emits when navStack is set and
  // the rendered node isn't the entry itself (defensive guard).
  function renderBackLink(node) {
    if (!navStack) return;
    if (node.Kind === 'entry') return;
    if (navStack.ID === node.ID) return;
    var entry = navStack;
    var back = el('button', { type: 'button', class: 'kp-back-link' });
    back.appendChild(el('span', { class: 'kp-back-arrow', text: '←' }));
    back.appendChild(document.createTextNode(' Back to '));
    var strong = document.createElement('strong');
    renderInline(entry.Title || 'entry point', strong);
    back.appendChild(strong);
    back.addEventListener('click', function() {
      // Returning to the entry resets the nav context — entry is the new root.
      openPanel(entry, back);
    });
    panelBody.appendChild(back);
  }

  // renderPanel composes the side-panel content for one node. All Finding-derived strings go
  // through textContent (via the el() helper) so untrusted content never reaches innerHTML.
  // Glossary/technique/category prose is HTML pre-vetted by Go and is allowed via 'html'.
  function renderPanel(node) {
    panelBody.innerHTML = '';
    panelTitle.textContent = '';
    renderInline(node.Title || 'Detail', panelTitle);

    renderBackLink(node);

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

    // For entry-point nodes, list every connected attack path as a tappable card.
    // This is the "modal that maps out the attack path" UX — on phones the panel is
    // a full-screen sheet, so the user lands on this list directly after tapping
    // the entry. On desktop the same list appears in the side panel.
    if (node.Kind === 'entry') {
      var pathSec = renderEntryPaths(node);
      if (pathSec) panelBody.appendChild(pathSec);
    }

    var category = node.RiskCategory && payload.Categories ? payload.Categories[node.RiskCategory] : null;
    if (category && node.Kind === 'impact') {
      var csec = el('section', { class: 'kp-section' }, [
        el('h4', { text: 'What this category means' }),
        el('div', { class: 'kp-prose', html: category.Plain || '' })
      ]);
      if (category.Examples && category.Examples.length) {
        var ul = el('ul', { class: 'kp-examples' });
        category.Examples.forEach(function(ex) {
          var li = document.createElement('li');
          renderInline(ex, li);
          ul.appendChild(li);
        });
        csec.appendChild(ul);
      }
      panelBody.appendChild(csec);
    }

    if (node.Description) {
      var descSec = el('section', { class: 'kp-section' }, [
        el('h4', { text: 'Why this finding fires' })
      ]);
      var descBody = el('div', { class: 'kp-prose' });
      renderMarkdownBlocks(node.Description, descBody);
      descSec.appendChild(descBody);
      panelBody.appendChild(descSec);
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

  // openPanel renders a node's detail into the side panel / mobile sheet and shows it.
  // opts.fromEntry: when set, records the entry node so the rendered cap panel can
  // show a "← Back to {entry}" link. Any other call path (direct SVG node click,
  // navigating back to the entry) clears navStack so we never carry a stale link
  // across an unrelated open.
  function openPanel(node, originEl, opts) {
    walkState = null;
    navStack = (opts && opts.fromEntry) ? opts.fromEntry : null;
    renderPanel(node);
    panel.hidden = false;
    panel.classList.add('kp-open');
    if (backdrop) {
      backdrop.hidden = false;
      // Two ticks so the transition fires after the element is laid out.
      requestAnimationFrame(function() { backdrop.classList.add('kp-backdrop-on'); });
    }
    document.body.classList.add('kp-modal-open');
    highlightNode(node);
    if (originEl) lastFocused = originEl;
    if (panelClose) panelClose.focus();
    // Reset internal scroll on re-open so a long previous panel doesn't strand
    // the user mid-content when a fresh node opens.
    panel.scrollTop = 0;
  }

  function closePanel() {
    panel.hidden = true;
    panel.classList.remove('kp-open');
    walkState = null;
    navStack = null;
    if (backdrop) {
      backdrop.classList.remove('kp-backdrop-on');
      backdrop.hidden = true;
    }
    document.body.classList.remove('kp-modal-open');
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
  // collected as separate copy-able code blocks AFTER the prose; everything
  // else flows through renderMarkdownBlocks so paragraphs, bullets, and
  // **bold** render correctly. All content goes through textContent — never
  // innerHTML — so analyzer strings can never inject markup.
  function renderRemediation(text) {
    var s = String(text || '');
    var commands = [];
    // Pull out command-shaped backtick spans up-front; replace them with a
    // sentinel so they vanish from the prose. Identifier-style backticks
    // (no spaces, not a known CLI) stay inline and render as <code>.
    var sanitized = s.replace(/`([^`]+)`/g, function(_, inner) {
      var isCmd = /\s/.test(inner) || /^(kubectl|kubeadm|helm|kubectl-)/.test(inner);
      if (isCmd) {
        commands.push(inner);
        return ''; // command renders as its own block below
      }
      return '`' + inner + '`';
    });
    var prose = el('div', { class: 'kp-prose' });
    renderMarkdownBlocks(sanitized, prose);
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
    // Use renderInlineHTML so backticks/**bold** in finding-derived text render
    // as <code>/<strong> instead of leaking through as raw markdown chars.
    if (node.Subtitle) lines.push('<div class="kp-tt-sub">' + renderInlineHTML(node.Subtitle) + '</div>');
    if (glossary && glossary.Short) lines.push('<div>' + renderInlineHTML(glossary.Short) + '</div>');
    if (node.Kind === 'capability' && node.Description) {
      lines.push('<div class="kp-tt-why"><span class="kp-tt-tag">Why it matters</span><br>' + renderInlineHTML(firstSentence(node.Description, 140)) + '</div>');
    }
    if (node.Kind === 'impact') {
      var cat = node.RiskCategory && payload.Categories ? payload.Categories[node.RiskCategory] : null;
      if (cat && cat.Examples && cat.Examples.length) {
        lines.push('<div class="kp-tt-why"><span class="kp-tt-tag">Example</span><br>' + renderInlineHTML(cat.Examples[0]) + '</div>');
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
  // Explicit backdrop click handler. The document-level mousedown handler further down
  // also closes on outside-click, but it doesn't always fire reliably on iOS Safari for
  // taps on otherwise-empty <div> overlays. A direct click handler on the backdrop is
  // the no-surprises path.
  if (backdrop) backdrop.addEventListener('click', closePanel);
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

// --- Inline glossary tooltips on <code class="gloss" data-glossary-key="..."> ---------
// Reuses the existing .kp-tooltip element (shared with the graph IIFE — only one tooltip
// is ever visible at a time, so this is safe). Glossary lookup goes through the same
// inline JSON payload that the graph side-panel reads. No-op when neither the tooltip
// element nor the payload is present (e.g. snapshots with zero findings).
(function() {
  var tooltip = document.querySelector('.kp-tooltip');
  if (!tooltip) return;
  var titleEl = tooltip.querySelector('.kp-tt-title');
  var bodyEl = tooltip.querySelector('.kp-tt-body');
  if (!titleEl || !bodyEl) return;

  var dataEl = document.getElementById('kp-graph-data');
  var glossary = {};
  if (dataEl) {
    try {
      var payload = JSON.parse(dataEl.textContent || '{}');
      glossary = (payload && payload.Glossary) || {};
    } catch (_) {
      glossary = {};
    }
  }
  if (!glossary || !Object.keys(glossary).length) return;

  function showFor(el, entry) {
    var rect = el.getBoundingClientRect();
    tooltip.style.left = (rect.left + window.pageXOffset + Math.min(rect.width / 2, 220)) + 'px';
    tooltip.style.top = (rect.top + window.pageYOffset - 12) + 'px';
    titleEl.textContent = entry.Title || '';
    if (entry.Short) {
      bodyEl.textContent = entry.Short;
      bodyEl.hidden = false;
    } else {
      bodyEl.textContent = '';
      bodyEl.hidden = true;
    }
    tooltip.hidden = false;
  }

  function glossTrigger(ev) {
    return ev.target.closest && ev.target.closest('code.gloss[data-glossary-key]');
  }
  function showGlossFor(el) {
    var entry = glossary[el.getAttribute('data-glossary-key')];
    if (!entry) return;
    showFor(el, entry);
  }
  function hideGloss() {
    tooltip.hidden = true;
  }
  document.addEventListener('mouseover', function(ev) {
    var el = glossTrigger(ev);
    if (el) showGlossFor(el);
  });
  document.addEventListener('mouseout', function(ev) {
    if (glossTrigger(ev)) hideGloss();
  });
  // Keyboard parity: focusing a code.gloss span (Tab into it) reveals the same tooltip,
  // and blurring hides it. Without this, keyboard-only users can't reach the glossary.
  document.addEventListener('focusin', function(ev) {
    var el = glossTrigger(ev);
    if (el) showGlossFor(el);
  });
  document.addEventListener('focusout', function(ev) {
    if (glossTrigger(ev)) hideGloss();
  });
  // Touch parity: tap toggles the tooltip. Tap on the same term again — or anywhere
  // outside the tooltip — dismisses. iOS dispatches `click` on a tap, so the same
  // listener covers both touch and mouse-click.
  document.addEventListener('click', function(ev) {
    var el = glossTrigger(ev);
    if (el) {
      if (tooltip.hidden) showGlossFor(el); else hideGloss();
      return;
    }
    if (!tooltip.hidden) hideGloss();
  });
  document.addEventListener('keydown', function(ev) {
    if (ev.key === 'Escape' && !tooltip.hidden) hideGloss();
  });
  // Hide on scroll so the tooltip doesn't drift away from its anchor.
  window.addEventListener('scroll', function() {
    if (!tooltip.hidden) tooltip.hidden = true;
  }, true);
})();
