const menuToggle = document.querySelector(".mobile-menu-toggle");
const navigation = document.querySelector(".primary-navigation");
const dropdownToggles = document.querySelectorAll(".nav-dropdown-toggle");
const supportToggle = document.querySelector(".support-button");
const supportPanel = document.querySelector("#support-panel");

function closeDropdowns(except = null) {
  document.querySelectorAll(".nav-item.is-open").forEach((item) => {
    if (item !== except) {
      item.classList.remove("is-open");
      item.querySelector(".nav-dropdown-toggle").setAttribute("aria-expanded", "false");
    }
  });
}

dropdownToggles.forEach((toggle) => {
  toggle.addEventListener("click", () => {
    const item = toggle.closest(".nav-item");
    const shouldOpen = !item.classList.contains("is-open");
    closeDropdowns(item);
    item.classList.toggle("is-open", shouldOpen);
    toggle.setAttribute("aria-expanded", String(shouldOpen));
  });
});

menuToggle.addEventListener("click", () => {
  const isOpen = menuToggle.getAttribute("aria-expanded") === "true";
  menuToggle.setAttribute("aria-expanded", String(!isOpen));
  menuToggle.setAttribute("aria-label", isOpen ? "Open navigation menu" : "Close navigation menu");
  navigation.classList.toggle("is-open", !isOpen);
  if (isOpen) closeDropdowns();
});

navigation.addEventListener("click", (event) => {
  if (event.target.closest("a")) {
    navigation.classList.remove("is-open");
    menuToggle.setAttribute("aria-expanded", "false");
    menuToggle.setAttribute("aria-label", "Open navigation menu");
    closeDropdowns();
  }
});

supportToggle.addEventListener("click", () => {
  const isOpen = supportToggle.getAttribute("aria-expanded") === "true";
  supportToggle.setAttribute("aria-expanded", String(!isOpen));
  supportToggle.setAttribute("aria-label", isOpen ? "Open support" : "Close support");
  supportPanel.hidden = isOpen;
});

document.addEventListener("click", (event) => {
  if (!event.target.closest(".nav-item")) closeDropdowns();
  if (!event.target.closest(".support")) {
    supportPanel.hidden = true;
    supportToggle.setAttribute("aria-expanded", "false");
    supportToggle.setAttribute("aria-label", "Open support");
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeDropdowns();
    navigation.classList.remove("is-open");
    menuToggle.setAttribute("aria-expanded", "false");
    menuToggle.setAttribute("aria-label", "Open navigation menu");
    supportPanel.hidden = true;
    supportToggle.setAttribute("aria-expanded", "false");
    supportToggle.setAttribute("aria-label", "Open support");
  }
});
