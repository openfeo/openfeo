// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Put the person's chosen theme on the page before it is first painted. This is a file of its
// own, loaded from the page's head, because the router's content security policy allows no
// inline script. The key is @openfeo/ui's THEME_KEY (a test keeps the two the same); with no
// choice stored the stylesheet follows the system.
;(function () {
  try {
    var theme = window.localStorage.getItem('openfeo.theme')
    if (theme === 'dark' || theme === 'light') {
      document.documentElement.setAttribute('data-theme', theme)
    }
  } catch {
    // Storage is blocked: the system's preference stands.
  }
})()
