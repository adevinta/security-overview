$(".parent-asset, .parent-vulnerability").click(function () {
  if (!$(this).hasClass("disabled")) {
    content = $(this).closest(".card").children(".card-content");
    icon = $(this).find(".fa-angle-up, .fa-angle-down")
    if (content.css("display") == "none") {
      content.css("display", "inherit");
      icon.removeClass("fa-angle-down").addClass("fa-angle-up");
    } else {
      content.css("display", "none");
      icon.removeClass("fa-angle-up").addClass("fa-angle-down");
    }
  }
});

$(document).keydown(function(e){
    if (e.key == "Escape") {
      closeAllModals();
    }
});

$(".child-vulnerability").click(function () {
  modal = $(this).parent().children(".modal");
  modal.addClass("is-active");
});

$(".modal-background, .modal-delete").click(function () {
  modal = $(this).closest(".modal");
  modal.removeClass("is-active");
});

$("#filter-parents-query").keyup(function (e) {
  query = $(this).val().toLowerCase();
  checkbox = $("#filter-info").find("input")[0];

  if ($("#tab-issues").hasClass("is-active")) {
    groups = $(this).closest(".columns").find(".group");
    $.each(groups, function (index, group) {
      group = $(group)
      if (group.children(".card-header").text().toLowerCase().indexOf(query) < 0) {
        group.css("display", "none");
      } else {
        if (group.hasClass("impact-0")) {
          if (checkbox.checked) {
            group.css("display", "none");
          } else {
            group.css("display", "inherit");
          }
        } else {
          group.css("display", "inherit");
        }
      }
    });
  } else if ($("#tab-assets").hasClass("is-active")) {
    assets = $(this).closest(".columns").find(".asset");
    $.each(assets, function (index, asset) {
      asset = $(asset)
      if (asset.children(".card-header").text().toLowerCase().indexOf(query) < 0) {
        asset.css("display", "none");
      } else {
        asset.css("display", "inherit");
      }
    });
  }
});

$(".filter-vulnerabilities").keyup(function (e) {
  query = $(this).val().toLowerCase();
  cards = $(this).closest(".card-content").find(".card");
  checkbox = $("#filter-info").find("input")[0];

  $.each(cards, function (index, card) {
    card = $(card)
    if (card.text().toLowerCase().indexOf(query) < 0) {
      card.css("display", "none");
    } else {
      if (card.hasClass("impact-0")) {
        if (checkbox.checked) {
          card.css("display", "none");
        } else {
          card.css("display", "inherit");
        }
      } else {
        card.css("display", "inherit");
      }
    }
  });
});

$("#filter-info").click(function () {
  checkbox = $(this).find("input")[0];
  checkbox.checked = !checkbox.checked;

  // Hide vulnerabilities with informational impact.
  $(".vulnerability").each(function (index, card) {
    card = $(card);
    if (card.hasClass("impact-0")) {
      if (checkbox.checked) {
        card.css("display", "none");
      } else {
        card.css("display", "inherit");
      }
    }
  });

  // Hide groups with informational impact.
  $(".group").each(function (index, card) {
    card = $(card);
    if (card.hasClass("impact-0")) {
      if (checkbox.checked) {
        card.css("display", "none");
      } else {
        card.css("display", "inherit");
      }
    }
  });

  // Hide assets with informational impact.
  $(".asset").each(function (index, card) {
    card = $(card);
    asset = card.find(".parent-asset");
    if (card.hasClass("impact-0")) {
      tag = $(this).find(".tag")
      check = $(this).find(".fa-check").parent();
      angle = $(this).find(".fa-angle-up, .fa-angle-down").parent();
      content = $(this).children(".card-content");
      if (checkbox.checked) {
        tag.css("display", "none");
        angle.css("display", "none");
        content.css("display", "none");
        check.css("display", "inherit");

        asset.addClass("disabled");
        angle.find(".fa").removeClass("fa-angle-up").addClass("fa-angle-down");
      } else {
        check.css("display", "none");
        tag.css("display", "inherit");
        angle.css("display", "inherit");

        asset.removeClass("disabled");
      }
    }
  });

  $(".filter-vulnerabilities").each(function (index) {
    $(this).val("");
    $(this).keyup();
  });
});

$(".clear-filter").click(function () {
  input = $(this).closest(".field").find("input");
  input.val("");
  input.keyup();
});

$(".delete").click(function () {
  $(this).closest(".notification").remove();
});

$(".tabs li").click(function (event) {
  tab = $(this);
  if (tab.hasClass("external-link-tab")) {
    // Handle tabs to external links.
    openUI(tab);
    return
  }
  if (!tab.hasClass("is-active")) {
    tab.addClass("is-active");
    if (tab.attr('id') == "tab-issues") {
      $("#tab-assets").removeClass("is-active");
      $("#tab-dashboard").removeClass("is-active");
      $("#assets").css("display", "none");
      $("#dashboard").css("display", "none");
      $("#issues").css("display", "");
      $("#filter-parents").css("display", "");
      $("#filter-parents-query").attr("placeholder", "Find an issue")
    } else if (tab.attr('id') == "tab-assets") {
      $("#tab-issues").removeClass("is-active");
      $("#tab-dashboard").removeClass("is-active");
      $("#issues").css("display", "none");
      $("#dashboard").css("display", "none");
      $("#assets").css("display", "");
      $("#filter-parents").css("display", "");
      $("#filter-parents-query").attr("placeholder", "Find an asset")
    } else if (tab.attr('id') == "tab-dashboard") {
      $("#tab-issues").removeClass("is-active");
      $("#tab-assets").removeClass("is-active");
      $("#issues").css("display", "none");
      $("#assets").css("display", "none");
      $("#dashboard").css("display", "");
      $("#filter-parents").css("display", "none");
    }
    $("#filter-parents-query").val("");
    $("#filter-parents-query").keyup();
  }
});

function getScanInfoFromUrl() {
  var qparams = (new URL(document.location)).searchParams;
  var info = {
    "team": qparams.get("team_id") || "",
    "scan": qparams.get("scan_id") || "",
  }
  return info
}

function openUI(tab) {
  var url = new URL(tab.data("url"));
  var info = getScanInfoFromUrl();

  url.searchParams.set("team_id", info.team)
  url.searchParams.set("scan_id", info.scan)
  window.open(url.toString(), "_blank");
}

function viewAssetVulnerability(target, summary) {
  vulnerabilities = $(document.getElementById(target)).find(".vulnerability").find(".modal");
  $.each(vulnerabilities, function (index, vulnerability) {
    vulnerability = $(vulnerability)
    if (vulnerability.text().indexOf(summary) >= 0) {
      var modal = vulnerability.clone();

      // Add asset target to table in modal.
      table = $(modal.find("table")[0]);
      row = $("<tr></tr>");
      colName = $("<td><strong>Asset<strong></td>");
      colValue = $("<td></td>");
      colValue.text(target);
      row.append(colName,colValue).prependTo(table);

      modal.appendTo("#issues");
      modal.addClass("is-active");
      modal.find(".modal-background, .modal-delete").click(function () {
        modal.removeClass("is-active");
        modal.remove();
      });
    }
  });
}

function closeAllModals() {
  modals = $(document).find(".modal");
  $.each(modals, function (index, modal) {
    modal = $(modal);
    modal.removeClass("is-active");
  });
}
function showReportProblem(issue, asset){
  var modal = $("#report-problem");
  $("#report-problem-issue").text(issue);
  $("#report-problem-asset").text(asset);
  $("#report-problem-reason").val("False Positive");
  $("#report-problem-comments").val("");
  modal.addClass("is-active");
}

function reportProblem(){
  var team = $("#report-problem-team").text();
  var scan = $("#report-problem-scan").text();
  var issue = $("#report-problem-issue").text();
  var asset = $("#report-problem-asset").text();
  var reason = $("#report-problem-reason").val();
  var comments = $("#report-problem-comments").val();
  if (reason == "Other") reason = "Problem";

  var url = "https://jira.mpi-internal.com/secure/CreateIssueDetails!init.jspa?pid=13680&issuetype=11711&priority=4&labels=Security&summary="+reason+"+in+"+team+"%27s+Report&description=I+would+like+to+report+a+problem+with+a+finding+in+our+Vulcan+report.%0a%0aReason:+"+reason+"%0aTeam:+"+team+"%0aScan:+"+scan+"%0aIssue:+"+issue+"%0aAsset:+"+asset+"%0aAdditional+comments:%0a"+encodeURI(comments);
  var w = window.open(url, "_blank");
  w.opener = null; // Prevent opener hijacking.
}
