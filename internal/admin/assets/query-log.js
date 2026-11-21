const results = document.querySelector("[data-query-results]");
results.classList.add("query-rows-clickable");
results.addEventListener("click", (event) => {
  const row = event.target.closest("[data-query-row]");
  if (!row || event.target.closest("summary") || window.getSelection()?.isCollapsed === false) return;
  const detail = row.querySelector("details");
  detail.open = !detail.open;
});

function setupPagination(more) {
  const status = document.querySelector("[data-query-status]");
  let loading = false;
  const observer = new IntersectionObserver((entries) => {
    if (entries.some((entry) => entry.isIntersecting)) void loadOlder();
  }, { rootMargin: "0px 0px 200px" });

  async function loadOlder() {
    if (loading) return;
    loading = true;
    observer.disconnect();
    status.textContent = "Loading older queries.";
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(more.href, { redirect: "error", signal: controller.signal });
      if (!response.ok) throw new Error("Query history request failed.");
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      const older = page.querySelector("[data-query-results]");
      if (!older) throw new Error("Query history is missing.");

      const groups = [...older.querySelectorAll("[data-query-date]")];
      const firstQuery = groups[0]?.querySelector("summary");
      for (const group of groups) {
        const lastGroup = results.tBodies[results.tBodies.length - 1];
        if (lastGroup.dataset.queryDate === group.dataset.queryDate) {
          // The cursor can split a UTC day across two pages.
          lastGroup.append(...[...group.rows].slice(1));
        } else {
          results.append(group);
        }
      }

      const next = page.querySelector("[data-query-more]");
      const moveFocus = document.activeElement === more;
      if (next) {
        more.href = next.getAttribute("href");
        status.textContent = "Older queries loaded.";
        observer.observe(more);
      } else {
        more.hidden = true;
        status.textContent = "No older queries remain.";
      }
      if (moveFocus) (firstQuery ?? status).focus();
    } catch {
      status.textContent = "Could not load older queries. Use Older queries to continue.";
      more.removeEventListener("click", onMoreClick);
    } finally {
      clearTimeout(timeout);
      loading = false;
    }
  }

  function onMoreClick(event) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    void loadOlder();
  }

  more.addEventListener("click", onMoreClick);
  observer.observe(more);
}

const more = document.querySelector("[data-query-more]");
if (more && "IntersectionObserver" in window) setupPagination(more);
