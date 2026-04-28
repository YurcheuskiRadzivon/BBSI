(function () {
  function $(s, el = document) {
    return el.querySelector(s);
  }

  const API_BASE = "";

  /** @returns {any[]} */
  function asArray(x) {
    return Array.isArray(x) ? x : [];
  }

  /** @returns {Promise<any>} */
  async function api(path, opt = {}) {
    const res = await fetch(API_BASE + path, {
      method: opt.method || "GET",
      headers: opt.body ? { "Content-Type": "application/json" } : undefined,
      body: opt.body ? JSON.stringify(opt.body) : undefined,
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch (_) {
      data = { error: text };
    }
    if (!res.ok) {
      const err = new Error(data.error || text || res.statusText);
      err.data = data;
      err.status = res.status;
      throw err;
    }
    return data;
  }

  async function sha256Hex(s) {
    const buf = new TextEncoder().encode(s);
    const h = await crypto.subtle.digest("SHA-256", buf);
    return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  function canonicalize(obj) {
    if (obj === null || obj === undefined) return null;
    const t = typeof obj;
    if (t !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(canonicalize);
    if (Object.prototype.toString.call(obj) !== "[object Object]") {
      if (obj instanceof Date) return obj.toISOString();
      return String(obj);
    }
    let keys;
    try {
      keys = Object.keys(obj).sort();
    } catch (_) {
      return String(obj);
    }
    const out = {};
    keys.forEach(k => {
      out[k] = canonicalize(obj[k]);
    });
    return out;
  }

  async function hashPayloadObject(obj) {
    const c = canonicalize(obj);
    return sha256Hex(JSON.stringify(c));
  }

  /** @typedef {{types:any[], emitters:any[], authorities:any[]}} Config */

  /** @type {Config|null} */
  let appConfig = null;

  /** Если выбран документ из реестра — отправляем те же payload, что в БД (иначе хэши могут не совпасть с issue). */
  let verifyRegistrySnap = null;

  function wireVerifySnapClear() {
    const ids = [
      "verify-document-id",
      "verify-document-type",
      "verify-title",
      "verify-year",
      "verify-institution",
      "verify-program",
      "verify-series",
      "verify-holder-ref",
      "verify-birth-year",
      "verify-personal-notes",
    ];
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener("input", () => {
        verifyRegistrySnap = null;
      });
      el.addEventListener("change", () => {
        verifyRegistrySnap = null;
      });
    });
  }

  async function loadConfig() {
    appConfig = await api("/api/config");
    const types = asArray(appConfig.types).filter(Boolean);
    const em = asArray(appConfig.emitters).filter(Boolean);

    function fillTypes(sel) {
      sel.innerHTML = "";
      types.forEach(t => {
        if (!t || typeof t !== "object") return;
        const o = document.createElement("option");
        o.value = t.id || "";
        o.textContent = t.label_ru || t.id || "";
        sel.appendChild(o);
      });
    }
    fillTypes($("#issue-document-type"));
    fillTypes($("#verify-document-type"));

    function fillEmitters(sel) {
      sel.innerHTML = "";
      em.forEach(e => {
        if (!e || typeof e !== "object") return;
        const o = document.createElement("option");
        o.value = e.code || "";
        o.textContent = `${e.code || ""} — ${e.name_ru || e.code || ""}`;
        sel.appendChild(o);
      });
    }
    fillEmitters($("#issue-issuer-country"));
    fillEmitters($("#issue-receiver-country"));
    fillEmitters($("#revoke-issuer"));

    $("#issue-issuer-country").addEventListener("change", () => refillAuthorities());

    refillAuthorities();
  }

  function refillAuthorities() {
    const cc = $("#issue-issuer-country").value;
    const sel = $("#issue-authority");
    const auth = asArray(appConfig && appConfig.authorities).filter(Boolean);
    sel.innerHTML = "";
    auth
      .filter(a => a && a.country_code === cc)
      .forEach(a => {
        const o = document.createElement("option");
        o.value = a.name_ru;
        o.textContent = a.name_ru;
        sel.appendChild(o);
      });
    if (!sel.options.length) {
      const o = document.createElement("option");
      o.value = "Authority";
      o.textContent = "— орган не найден в authorities.json —";
      sel.appendChild(o);
    }
  }

  function fieldByPrefix(prefix, name) {
    const id = prefix === "issue" ? `issue-${name}` : `verify-${name}`;
    const el = document.getElementById(id);
    return el ? String(el.value).trim() : "";
  }

  function docPayloadFromForm(prefix) {
    const get = name => fieldByPrefix(prefix, name);
    const yearRaw =
      prefix === "issue"
        ? fieldByPrefix("issue", "year")
        : fieldByPrefix("verify", "year");
    const yearNum = Number(yearRaw);
    return {
      title: get("title"),
      year: Number.isFinite(yearNum) ? yearNum : 0,
      institution: get("institution"),
      program: get("program"),
      series_number: get("series"),
    };
  }

  function metaPayloadFromForm(prefix) {
    const holder =
      prefix === "issue"
        ? fieldByPrefix("issue", "holder-ref")
        : fieldByPrefix("verify", "holder-ref");
    const by =
      prefix === "issue"
        ? fieldByPrefix("issue", "birth-year")
        : fieldByPrefix("verify", "birth-year");
    const notes =
      prefix === "issue"
        ? fieldByPrefix("issue", "personal-notes")
        : fieldByPrefix("verify", "personal-notes");
    if (!holder && !by && !notes) return null;
    const o = {
      holder_ref: holder || "",
      personal_notes: notes || "",
    };
    if (by) o.birth_year = Number(by);
    return o;
  }

  async function refreshHashDisplays(prefix) {
    const dp = docPayloadFromForm(prefix);
    const mp = metaPayloadFromForm(prefix);
    const outD =
      prefix === "issue" ? $("#issue-doc-hash-out") : $("#verify-doc-hash-out");
    const outM =
      prefix === "issue" ? $("#issue-meta-hash-out") : $("#verify-meta-hash-out");
    try {
      outD.textContent = await hashPayloadObject(dp);
    } catch (e) {
      outD.textContent = String(e);
    }
    if (!mp) {
      outM.textContent = "— нет персональных полей —";
      return;
    }
    try {
      outM.textContent = await hashPayloadObject(mp);
    } catch (e) {
      outM.textContent = String(e);
    }
  }

  function bindFormHashPreview(prefix) {
    const ids =
      prefix === "issue"
        ? [
            "issue-title",
            "issue-year",
            "issue-institution",
            "issue-program",
            "issue-series",
            "issue-holder-ref",
            "issue-birth-year",
            "issue-personal-notes",
          ]
        : [
            "verify-title",
            "verify-year",
            "verify-institution",
            "verify-program",
            "verify-series",
            "verify-holder-ref",
            "verify-birth-year",
            "verify-personal-notes",
          ];
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", () => refreshHashDisplays(prefix));
    });
  }

  async function loadDocumentsRegistry(issueNodes) {
    try {
      const data = await api("/api/documents");
      const docs = asArray(data.documents).filter(Boolean);
      const sel = $("#verify-doc-registry");
      const illegal = $("#illegal-doc");
      sel.innerHTML = '<option value="">— выберите документ —</option>';
      illegal.innerHTML = "";
      const seenIllegal = new Set();

      docs.forEach(d => {
        seenIllegal.add(d.document_id);
        const o = document.createElement("option");
        o.value = d.document_id;
        o.textContent = `${d.document_id} (${d.last_action || ""})`;
        sel.appendChild(o);

        illegal.appendChild(new Option(d.document_id, d.document_id));
      });

      (issueNodes || []).forEach(n => {
        const did = n.transaction && n.transaction.document_id;
        if (!did || seenIllegal.has(did)) return;
        seenIllegal.add(did);
        illegal.appendChild(new Option(`${did} (только в графе)`, did));
      });

      sel.onchange = async () => {
        const id = sel.value;
        if (!id) {
          verifyRegistrySnap = null;
          return;
        }
        const doc = docs.find(x => x && x.document_id === id);
        if (!doc) {
          verifyRegistrySnap = null;
          const vid = $("#verify-document-id");
          if (vid) vid.value = id;
          return;
        }
        verifyRegistrySnap = doc;
        $("#verify-document-id").value = doc.document_id;
        $("#verify-document-type").value = doc.document_type || "diploma";

        const dp =
          typeof doc.document_payload === "object" && doc.document_payload !== null
            ? doc.document_payload
            : {};
        $("#verify-title").value = dp.title || "";
        $("#verify-year").value = dp.year || "";
        $("#verify-institution").value = dp.institution || "";
        $("#verify-program").value = dp.program || "";
        $("#verify-series").value = dp.series_number || "";

        const mp =
          typeof doc.metadata_payload === "object" && doc.metadata_payload !== null
            ? doc.metadata_payload
            : {};
        $("#verify-holder-ref").value = mp.holder_ref || "";
        $("#verify-birth-year").value = mp.birth_year || "";
        $("#verify-personal-notes").value = mp.personal_notes || "";

        await refreshHashDisplays("verify");
      };
    } catch (_) {}
  }

  function appendLog(which, msg) {
    const ta =
      which === "attack"
        ? /** @type {HTMLTextAreaElement} */ ($("#attack-log"))
        : /** @type {HTMLTextAreaElement} */ ($("#ops-log"));
    if (!ta) return;
    ta.value += `[${new Date().toISOString()}] ${msg}\n`;
    ta.scrollTop = ta.scrollHeight;
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length <= n ? s : s.slice(0, n) + "…";
  }

  /** Разбить строку на несколько строк фиксированной ширины (для подписей в DAG). */
  function chunkLines(str, chunkLen, maxLines) {
    const s = String(str || "");
    if (!s.length) return [""];
    const out = [];
    let i = 0;
    while (i < s.length && out.length < maxLines) {
      const remaining = s.length - i;
      const slotsLeft = maxLines - out.length;
      if (slotsLeft === 1 && remaining > chunkLen) {
        out.push(s.slice(i, i + chunkLen - 1) + "…");
        break;
      }
      const take = Math.min(chunkLen, remaining);
      out.push(s.slice(i, i + take));
      i += take;
    }
    return out;
  }

  function computeDepth(nodes) {
    const list = asArray(nodes).filter(n => n && n.transaction);
    const byId = {};
    for (const n of list) byId[n.transaction.tx_id] = n;
    const depth = {};
    const visit = id => {
      if (depth[id] !== undefined) return depth[id];
      const n = byId[id];
      if (!n || !n.parent_ids || !n.parent_ids.length) {
        depth[id] = 0;
        return 0;
      }
      let max = -1;
      for (const p of n.parent_ids) max = Math.max(max, visit(p));
      depth[id] = max + 1;
      return depth[id];
    };
    for (const n of list) visit(n.transaction.tx_id);
    return depth;
  }

  function layoutDAG(nodesIn) {
    const svgEl = $("#dag-svg");
    if (!svgEl) return;

    const nodes = asArray(nodesIn).filter(n => n && n.transaction);
    const depth = computeDepth(nodes);
    const layers = {};
    let maxD = 0;
    for (const n of nodes) {
      const d = depth[n.transaction.tx_id];
      if (!layers[d]) layers[d] = [];
      layers[d].push(n);
      maxD = Math.max(maxD, d);
    }
    Object.keys(layers).forEach(k => {
      layers[k].sort((a, b) =>
        String(a.transaction.tx_id).localeCompare(String(b.transaction.tx_id))
      );
    });

    /* Крупные карточки узла: ширина/высота задают реальный размер в SVG (пиксели), без масштабирования под окно */
    const nw = 300;
    const lineStep = 16;
    const padTextTop = 16;
    const gapX = 44;
    /* расстояние между слоями по вертикали: высота карточки + зазор под стрелки */
    const gapBetweenLayers = 56;
    let maxRow = 1;
    Object.keys(layers).forEach(k => {
      maxRow = Math.max(maxRow, layers[k].length);
    });
    const layersCount = maxD + 1;
    const padX = 52;
    const padY = 48;
    const nh =
      padTextTop +
      10 * lineStep +
      14; /* до ~10 строк текста */
    const rowH = nh + gapBetweenLayers;
    const W = Math.max(1100, padX * 2 + maxRow * (nw + gapX));
    const H = Math.max(640, padY * 2 + layersCount * rowH);

    /** @type {Record<string,{x:number,y:number}>} */
    const pos = {};

    Object.keys(layers).forEach(dl => {
      const d = +dl;
      const row = layers[d];
      const colW = (W - padX * 2) / Math.max(1, row.length);
      row.forEach((node, i) => {
        const cx = padX + colW * i + colW / 2;
        const cy = padY + d * rowH + rowH / 2;
        pos[node.transaction.tx_id] = { x: cx, y: cy };
      });
    });

    function svgElt(name, attrs) {
      const n = document.createElementNS("http://www.w3.org/2000/svg", name);
      const a = attrs && typeof attrs === "object" ? attrs : {};
      Object.entries(a).forEach(([k, v]) => {
        if (v !== undefined && v !== null) n.setAttribute(k, String(v));
      });
      return n;
    }

    const svg = svgEl;
    svg.innerHTML = "";

    const defs = svgElt("defs");
    const mk = svgElt("marker", {
      id: "arrow",
      markerWidth: "10",
      markerHeight: "10",
      refX: "8",
      refY: "4",
      orient: "auto",
      markerUnits: "strokeWidth",
    });
    mk.appendChild(svgElt("path", { d: "M0,0 L10,4 L0,8 z", fill: "#6b90b0" }));
    defs.appendChild(mk);
    svg.appendChild(defs);

    nodes.forEach(n => {
      if (!n || !n.transaction) return;
      const from = pos[n.transaction.tx_id];
      if (!from) return;
      const parents = n.parent_ids || [];
      for (const pid of parents) {
        const to = pos[pid];
        if (!to) continue;
        svg.appendChild(
          svgElt("line", {
            x1: from.x,
            y1: from.y,
            x2: to.x,
            y2: to.y,
            stroke: "#5c7a94",
            "stroke-width": 2,
            "marker-end": "url(#arrow)",
          })
        );
      }
    });

    const actionColors = {
      issue: "#1e4d78",
      revoke: "#7c2828",
    };

    nodes.forEach(n => {
      if (!n || !n.transaction) return;
      const p = pos[n.transaction.tx_id];
      if (!p) return;
      const tx = n.transaction;
      const ac = String(tx.action || "");
      const fill = actionColors[ac] || "#333f50";

      const rect = svgElt("rect", {
        x: p.x - nw / 2,
        y: p.y - nh / 2,
        width: nw,
        height: nh,
        rx: "8",
        fill,
        stroke: "#9dc5f0",
        "stroke-width": "1.5",
      });
      svg.appendChild(rect);

      const mono =
        'ui-monospace, Consolas, "Cascadia Mono", monospace';

      const rows = [];
      chunkLines(tx.tx_id, 18, 2).forEach(line =>
        rows.push({ text: line, small: true })
      );
      rows.push({
        text: `${String(ac).toUpperCase()} · ${truncate(tx.document_type || "?", 28)}`,
        em: true,
      });
      chunkLines(tx.document_id, 26, 2).forEach(line =>
        rows.push({ text: line || "—", small: true })
      );
      rows.push({
        text: `${tx.issuer_country || "?"} → ${tx.receiver_country || "?"}`,
      });
      chunkLines(tx.document_hash || "", 22, 4).forEach(line =>
        rows.push({ text: line, small: true })
      );

      rows.forEach((row, i) => {
        const t = svgElt("text", {
          x: p.x,
          y: p.y - nh / 2 + padTextTop + i * lineStep,
          fill: "#f2f7fd",
          "font-size": row.small ? "11" : "11.75",
          "font-weight": row.em ? "600" : "400",
          "text-anchor": "middle",
          "font-family": mono,
        });
        t.textContent = row.text;
        svg.appendChild(t);
      });

      const tit = svgElt("title");
      tit.textContent = `${tx.tx_id}\naction=${tx.action}\ntype=${tx.document_type}\ndoc=${tx.document_id}\nissuer=${tx.issuer_authority}\nnode_hash=${n.node_hash}`;
      rect.appendChild(tit);
    });

    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("width", String(W));
    svg.setAttribute("height", String(H));
  }

  async function refreshDAG() {
    const data = await api("/api/dag");
    const nodes = asArray(data.nodes).filter(n => n && n.transaction);
    layoutDAG(nodes);
    $("#dag-meta").textContent = `${nodes.length} узлов · стрелка к родителю`;

    const forge = $("#sel-forge");
    const issuerSel = $("#sel-issuer");
    forge.innerHTML = "";
    issuerSel.innerHTML = "";

    const issueNodes = nodes.filter(
      n => n.transaction && n.transaction.action === "issue"
    );

    if (!issueNodes.length) {
      forge.appendChild(new Option("— создайте выдачу (issue) —", ""));
    } else {
      issueNodes.forEach(n => {
        const id = n.transaction.tx_id;
        forge.appendChild(
          new Option(`${truncate(id, 10)} · ${n.transaction.document_id}`, id)
        );
      });
    }

    if (!nodes.length) {
      issuerSel.appendChild(new Option("— нет узлов —", ""));
    } else {
      nodes.forEach(n => {
        if (!n.transaction) return;
        const id = n.transaction.tx_id;
        issuerSel.appendChild(
          new Option(`${truncate(id, 10)} · ${n.transaction.action}`, id)
        );
      });
    }

    await loadDocumentsRegistry(issueNodes);
  }

  async function pollLogs() {
    try {
      const data = await api("/api/logs");
      const entries = asArray(data.entries);
      $("#ops-log").value = entries
        .map(e => {
          if (!e || typeof e !== "object") return "";
          const t = typeof e.time === "number" ? e.time : 0;
          return `[${new Date(t).toISOString()}] [${e.level || ""}] ${e.message || ""}`;
        })
        .filter(Boolean)
        .join("\n");
    } catch (_) {}
    try {
      const al = await api("/api/attack-logs");
      $("#attack-log").value = asArray(al.lines).join("\n");
    } catch (_) {}
  }

  async function bind() {
    await loadConfig();
    wireVerifySnapClear();
    bindFormHashPreview("issue");
    bindFormHashPreview("verify");
    await refreshHashDisplays("issue");
    await refreshHashDisplays("verify");

    $("#btn-refresh").onclick = async () => {
      try {
        await refreshDAG();
        appendLog("ops", "граф обновлён");
      } catch (e) {
        appendLog("ops", String(e));
      }
    };

    $("#form-issue").onsubmit = async ev => {
      ev.preventDefault();
      try {
        const payload = docPayloadFromForm("issue");
        const meta = metaPayloadFromForm("issue");
        const body = {
          document_id: $("#issue-document-id").value.trim(),
          document_type: $("#issue-document-type").value,
          document_payload: payload,
          issuer_country: $("#issue-issuer-country").value,
          issuer_authority: $("#issue-authority").value,
          receiver_country: $("#issue-receiver-country").value,
          parent_ids: [],
        };
        if (meta) body.metadata_payload = meta;
        await api("/api/tx/issue", { method: "POST", body });
        appendLog("ops", "issue OK");
        await refreshDAG();
      } catch (e) {
        appendLog("ops", "issue: " + /** @type {Error} */ (e).message);
      }
    };

    $("#form-verify").onsubmit = async ev => {
      ev.preventDefault();
      const vr = /** @type {HTMLElement} */ ($("#verify-result"));
      try {
        const docId = $("#verify-document-id").value.trim();
        const body = { document_id: docId };
        if (verifyRegistrySnap && verifyRegistrySnap.document_id === docId) {
          body.document_payload =
            verifyRegistrySnap.document_payload !== undefined
              ? verifyRegistrySnap.document_payload
              : docPayloadFromForm("verify");
          if (
            verifyRegistrySnap.metadata_payload !== undefined &&
            verifyRegistrySnap.metadata_payload !== null
          ) {
            body.metadata_payload = verifyRegistrySnap.metadata_payload;
          }
        } else {
          body.document_payload = docPayloadFromForm("verify");
          const m = metaPayloadFromForm("verify");
          if (m) body.metadata_payload = m;
        }
        const res = await api("/api/verify", { method: "POST", body });
        const summary =
          res.summary_ru ||
          `${res.status || "?"} (summary_ru не пришёл — обновите бэкенд).`;
        vr.hidden = false;
        vr.classList.remove("ok", "bad");
        vr.classList.add(res.ok ? "ok" : "bad");
        vr.textContent = summary;
        appendLog("ops", `verify: ${res.status} ok=${res.ok}`);
      } catch (e) {
        vr.hidden = false;
        vr.classList.remove("ok", "bad");
        vr.classList.add("bad");
        vr.textContent = /** @type {Error} */ (e).message || String(e);
        appendLog("ops", "verify: " + /** @type {Error} */ (e).message);
      }
    };

    $("#form-revoke").onsubmit = async ev => {
      ev.preventDefault();
      const fd = new FormData(/** @type {HTMLFormElement} */ (ev.target));
      try {
        await api("/api/tx/revoke", {
          method: "POST",
          body: {
            document_id: fd.get("document_id"),
            issuer_country: fd.get("issuer_country"),
            parent_ids: [],
          },
        });
        appendLog("ops", "revoke OK");
        await refreshDAG();
      } catch (e) {
        appendLog("ops", "revoke: " + /** @type {Error} */ (e).message);
      }
    };

    $("#btn-validate").onclick = async () => {
      const vr = /** @type {HTMLElement} */ ($("#validate-result"));
      try {
        const v = await api("/api/validate");
        const summary =
          v.summary_ru ||
          (v.ok
            ? "ИТОГ: успешно (summary_ru не пришёл — обновите бэкенд)."
            : "ИТОГ: ошибки (summary_ru не пришёл).");
        vr.hidden = false;
        vr.classList.remove("ok", "bad");
        vr.classList.add(v.ok ? "ok" : "bad");
        vr.textContent = summary;
        await pollLogs();
      } catch (e) {
        appendLog("ops", String(e));
        vr.hidden = false;
        vr.classList.remove("ok", "bad");
        vr.classList.add("bad");
        vr.textContent = String(e);
      }
    };

    $("#btn-gossip").onclick = async () => {
      try {
        const g = await api("/api/gossip");
        appendLog(
          "ops",
          `gossip events=${(g.events || []).length} votes=${(g.votes || []).length}`
        );
      } catch (e) {
        appendLog("ops", String(e));
      }
    };

    $("#btn-seed").onclick = async () => {
      try {
        const docId = "DEMO-" + Math.random().toString(36).slice(2, 8);
        const docPayload = {
          title: "Диплом (демо)",
          year: 2024,
          institution: "БГУ",
          program: "Информатика",
          series_number: "Д-" + docId.slice(-4),
        };
        const metaPayload = {
          holder_ref: "ref-" + docId,
          birth_year: 1999,
          personal_notes: "демо",
        };
        await api("/api/tx/issue", {
          method: "POST",
          body: {
            document_id: docId,
            document_type: "diploma",
            document_payload: docPayload,
            metadata_payload: metaPayload,
            issuer_country: "BY",
            issuer_authority: "Министерство образования РБ",
            receiver_country: "RU",
            parent_ids: [],
          },
        });
        appendLog("ops", "демо: выпуск issue готов (verify — отдельная кнопка «Проверить», без узла в DAG)");
        await refreshDAG();
      } catch (e) {
        appendLog("ops", String(e));
      }
    };

    $("#btn-clear-attack-log").onclick = async () => {
      await fetch(API_BASE + "/api/attack-logs", { method: "DELETE" });
      $("#attack-log").value = "";
    };

    $("#btn-reset-db").onclick = async () => {
      if (
        !confirm(
          "Полностью очистить данные БД?\n\n• узлы DAG и gossip\n• документы в реестре\n• логи и журнал атак\n• новые ключи подписи эмитентов\n\nСправочники стран и типов останутся.\n\nТекущий сеанс сервера обновит память после сброса."
        )
      ) {
        return;
      }
      const msg = $("#reset-db-msg");
      msg.textContent = "Сброс…";
      msg.className = "mt muted";
      try {
        const res = await fetch(API_BASE + "/api/db/reset", { method: "POST" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          msg.textContent = data.error || String(res.status);
          msg.className = "mt status-bad";
          return;
        }
        msg.textContent = data.message || "Готово.";
        msg.className = "mt status-good";
        $("#attack-log").value = "";
        const vr = $("#validate-result");
        vr.hidden = true;
        vr.textContent = "";
        await refreshDAG();
        await pollLogs();
        appendLog("ops", "[сброс БД] " + (data.message || "OK"));
      } catch (e) {
        msg.textContent = String(e);
        msg.className = "mt status-bad";
      }
    };

    $("#btn-attack-forge").onclick = async () => {
      const txId = $("#sel-forge").value;
      if (!txId) {
        appendLog("attack", "Выберите узел issue или выполните выдачу.");
        return;
      }
      try {
        const fake = await sha256Hex("FORGED-" + Date.now());
        const steps = await api("/api/attacks/forgery", {
          method: "POST",
          body: { tx_id: txId, fake_hash: fake },
        });
        $("#attack-log").value += (steps.steps || []).join("\n") + "\n";
      } catch (e) {
        appendLog("attack", String(e));
      }
      await pollLogs();
      await refreshDAG();
    };

    $("#btn-attack-issuer").onclick = async () => {
      const txId = $("#sel-issuer").value;
      const nc = $("#new-country").value || "RU";
      if (!txId) return;
      try {
        const steps = await api("/api/attacks/issuer", {
          method: "POST",
          body: { tx_id: txId, new_country: nc },
        });
        $("#attack-log").value += (steps.steps || []).join("\n") + "\n";
      } catch (e) {
        appendLog("attack", String(e));
      }
      await pollLogs();
      await refreshDAG();
    };

    $("#btn-attack-revoke").onclick = async () => {
      const doc = $("#illegal-doc").value;
      const wrong = $("#wrong-country").value || "KZ";
      if (!doc) {
        appendLog("attack", "Нет документов в реестре.");
        return;
      }
      const res = await fetch(API_BASE + "/api/attacks/illegal-revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          document_id: doc,
          wrong_country: wrong,
          parent_ids: [],
        }),
      });
      const text = await res.text();
      try {
        const data = JSON.parse(text);
        $("#attack-log").value += (data.steps || []).join("\n") + "\n";
      } catch (_) {
        $("#attack-log").value += text + "\n";
      }
      await pollLogs();
      await refreshDAG();
    };

    try {
      await refreshDAG();
    } catch (e) {
      appendLog("ops", "нет связи с сервером: " + String(e));
    }
    pollLogs();
    setInterval(pollLogs, 5000);
  }

  document.addEventListener("DOMContentLoaded", bind);
})();
