if (navigator.clipboard) {
  document.querySelectorAll(".terminal .copyable").forEach((code) => {
    const caption = code.closest("figure").querySelector("figcaption");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy shell commands");
    button.setAttribute("aria-live", "polite");

    let reset;
    button.addEventListener("click", async () => {
      clearTimeout(reset);
      try {
        await navigator.clipboard.writeText(code.textContent);
        button.textContent = "Copied";
        button.setAttribute("aria-label", "Commands copied");
      } catch {
        button.textContent = "Copy failed";
        button.setAttribute("aria-label", "Copy failed. Select the commands to copy them.");
      }
      reset = setTimeout(() => {
        button.textContent = "Copy";
        button.setAttribute("aria-label", "Copy shell commands");
      }, 2500);
    });

    caption.append(button);
  });
}
