const links = {
  openPhishAnalyze: "https://phishanalyze.mdpstudio.com.au/analyze",
  openPayShield: "https://payshield.mdpstudio.com.au/app",
};

Object.entries(links).forEach(([id, url]) => {
  document.getElementById(id).addEventListener("click", () => {
    chrome.tabs.create({ url });
  });
});
