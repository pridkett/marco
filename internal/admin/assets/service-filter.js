const editor = document.querySelector("[data-service-editor]");
const choices = editor.querySelector("[data-service-choices]");

if (choices) {
  const searchBar = editor.querySelector("[data-service-search]");
  const search = searchBar.querySelector("[data-search]");
  const category = searchBar.querySelector("[data-category]");
  const blockedOnly = searchBar.querySelector("[data-blocked-only]");
  const empty = editor.querySelector("[data-no-services]");
  const summary = editor.querySelector("[data-service-summary]");
  const services = Array.from(choices.querySelectorAll("[data-service]"), (row) => {
    const input = row.querySelector("input");
    return {
      row,
      input,
      inherited: row.dataset.inherited === "true",
      custom: input.checked,
      text: row.dataset.searchText.toLowerCase(),
    };
  });

  function render() {
    const inherits = editor.elements.mode.value === "inherit";
    const query = search.value.trim().toLowerCase();
    let blocked = 0;
    let shown = 0;
    choices.disabled = inherits;

    for (const service of services) {
      service.input.checked = inherits ? service.inherited : service.custom;
      if (service.input.checked) blocked++;
      const visible = service.text.includes(query)
        && (!category.value || service.row.dataset.category === category.value)
        && (!blockedOnly.checked || service.input.checked);
      service.row.hidden = !visible;
      if (visible) shown++;
    }

    empty.hidden = shown !== 0;
    const state = inherits ? " by inheritance" : "";
    const message = `${blocked} of ${services.length} services blocked${state}.`;
    if (summary.textContent !== message) summary.textContent = message;
  }

  for (const service of services) {
    service.input.addEventListener("change", () => {
      service.custom = service.input.checked;
      render();
    });
  }
  for (const radio of editor.elements.mode) radio.addEventListener("change", render);
  searchBar.addEventListener("input", render);
  searchBar.hidden = false;
  render();
}
