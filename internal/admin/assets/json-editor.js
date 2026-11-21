(() => {
  'use strict';

  // Keep large imports editable without adding an unbounded number of DOM nodes.
  const maxHighlightLength = 256 * 1024;
  const maxTokens = 16000;
  const maxLines = 16000;

  function highlight(source) {
    if (source.length > maxHighlightLength) return null;

    const fragment = document.createDocumentFragment();
    // Recognize unfinished strings so the draft stays readable during typing.
    const tokens = /"(?:[^"\\\n]|\\[^\n])*"?|[{}\[\],:]+|[^\s"{}\[\],:]+/g;
    const property = /\s*:/y;
    let end = 0;
    let count = 0;
    for (const { 0: token, index } of source.matchAll(tokens)) {
      if (++count > maxTokens) return null;
      if (index > end) fragment.append(source.slice(end, index));
      end = index + token.length;

      let kind;
      if (token.startsWith('"')) {
        property.lastIndex = end;
        kind = token.length > 1 && token.endsWith('"') && property.test(source) ? 'key' : 'string';
      } else if (/^(?:true|false|null)$/.test(token)) {
        kind = 'literal';
      } else if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:e[+-]?\d+)?$/i.test(token)) {
        kind = 'number';
      } else if (/^[{}\[\],:]/.test(token)) {
        kind = 'punctuation';
      }
      if (kind) {
        const span = document.createElement('span');
        span.className = 'json-' + kind;
        span.textContent = token;
        fragment.append(span);
      } else {
        fragment.append(token);
      }
    }
    fragment.append(source.slice(end));
    return fragment;
  }

  function enhance(textarea) {
    const editor = document.createElement('span');
    editor.className = 'json-editor';
    const gutter = document.createElement('span');
    gutter.className = 'json-editor-gutter';
    gutter.setAttribute('aria-hidden', 'true');
    const lines = document.createElement('span');
    gutter.append(lines);

    const surface = document.createElement('span');
    surface.className = 'json-editor-surface';
    const backdrop = document.createElement('span');
    backdrop.className = 'json-editor-backdrop';
    backdrop.setAttribute('aria-hidden', 'true');
    const code = document.createElement('span');
    backdrop.append(code);

    textarea.before(editor);
    surface.append(backdrop, textarea);
    editor.append(gutter, surface);

    function syncScroll() {
      code.style.transform = 'translate(' + -textarea.scrollLeft + 'px, ' + -textarea.scrollTop + 'px)';
      lines.style.transform = 'translateY(' + -textarea.scrollTop + 'px)';
    }

    function render() {
      const source = textarea.value;
      const rowCount = source.split('\n', maxLines + 1).length;
      const colored = rowCount <= maxLines ? highlight(source) : null;
      code.replaceChildren(colored || '');
      lines.textContent = colored ? Array.from({ length: rowCount }, (_, index) => index + 1).join('\n') : '';
      editor.classList.toggle('is-highlighted', Boolean(colored));
      syncScroll();
    }

    const resize = new ResizeObserver(() => {
      // Match the native text viewport, excluding its scrollbars and resize handle.
      backdrop.style.width = textarea.clientWidth + 'px';
      backdrop.style.height = gutter.style.maxHeight = textarea.clientHeight + 'px';
      syncScroll();
    });
    resize.observe(textarea);
    textarea.addEventListener('scroll', syncScroll);
    textarea.addEventListener('input', render);
    textarea.addEventListener('compositionstart', () => editor.classList.add('is-composing'));
    textarea.addEventListener('compositionend', () => editor.classList.remove('is-composing'));
    window.addEventListener('pageshow', render);
    render();
  }

  if ('ResizeObserver' in window) {
    document.querySelectorAll('textarea[data-json-editor]').forEach(enhance);
  }
  for (const output of document.querySelectorAll('[data-json-output]')) {
    const colored = highlight(output.textContent);
    if (colored) output.replaceChildren(colored);
  }
})();
