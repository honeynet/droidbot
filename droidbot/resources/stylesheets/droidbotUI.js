var network = null;

function draw() {
  var utg_div = document.getElementById('utg_div');
  var utg_details = document.getElementById('utg_details');

  showOverall();

  var options = {
    autoResize: true,
    height: '100%',
    width: '100%',
    locale: 'en',

    nodes: {
      color: {
        border: '#000',
        background: '#000'
      },
      font:{
        size: 12,
        color:'#000'
      }
    },
    edges: {
      color: 'black',
      arrows: {
        to: {
          enabled: true,
          scaleFactor: 0.5
        }
      },
      font:{
        size: 12,
        color:'#000'
      }
    }
  };

  network = new vis.Network(utg_div, utg, options);

  network.on("click", function (params) {
    if (params.nodes.length > 0) {
      node = params.nodes[0];
      utg_details.innerHTML = '<h2>State Details</h2>\n' + getNodeDetails(node);
    }
    else if (params.edges.length > 0) {
      edge = params.edges[0];
      utg_details.innerHTML = '<h2>Edge Details</h2>\n' + getEdgeDetails(edge);
    }
  });
}

function showOverall() {
  var utg_details = document.getElementById('utg_details');
  utg_details.innerHTML = getOverallResult();
}

function getOverallResult() {
  var overallInfo = "<hr />";
  overallInfo += "<h4>App information</h4>\n<table class=\"table\">\n";
  overallInfo += "<tr><th class=\"col-md-1\">Package</th><td class=\"col-md-4\">" + utg.app_package + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">SHA-256</th><td class=\"col-md-4\">" + utg.app_sha256 + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">MainActivity</th><td class=\"col-md-4\">" + utg.app_main_activity + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># activities</th><td class=\"col-md-4\">" + utg.app_num_total_activities + "</td></tr>\n";
  overallInfo += "</table>";

  overallInfo += "<h4>Device information</h4>\n<table class=\"table\">\n";
  overallInfo += "<tr><th class=\"col-md-1\">Device serial</th><td class=\"col-md-4\">" + utg.device_serial + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Model number</th><td class=\"col-md-4\">" + utg.device_model_number + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">SDK version</th><td class=\"col-md-4\">" + utg.device_sdk_version + "</td></tr>\n";
  overallInfo += "</table>";

  overallInfo += "<h4>DroidBot result</h4>\n<table class=\"table\">\n";
  overallInfo += "<tr><th class=\"col-md-1\">Test date</th><td class=\"col-md-4\">" + utg.test_date + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Time spent (s)</th><td class=\"col-md-4\">" + utg.time_spent + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># input events</th><td class=\"col-md-4\">" + utg.num_input_events + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># UTG states</th><td class=\"col-md-4\">" + utg.num_nodes + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># UTG edges</th><td class=\"col-md-4\">" + utg.num_edges + "</td></tr>\n";
  activity_coverage = 100 * utg.num_reached_activities / utg.app_num_total_activities;
  overallInfo += "<tr><th class=\"col-md-1\">Activity Coverage</th><td class=\"col-md-4 progress\"><div class=\"progress-bar\" role=\"progressbar\" aria-valuenow=\"" + utg.num_reached_activities + "\" aria-valuemin=\"0\" aria-valuemax=\"" + utg.app_num_total_activities + "\" style=\"width: " + activity_coverage + "%;\">" + utg.num_reached_activities + "/" + utg.app_num_total_activities + "</div></td></tr>\n";
  overallInfo += "</table>";
  return overallInfo;
}

function getEdgeDetails(edgeId) {
  var i, numEdges;
  numEdges = utg.edges.length;
  for (i = 0; i < numEdges; i++) {
    if (utg.edges[i].id == edgeId) {
      return utg.edges[i];
    }
  }
  return "";
}

function getNodeDetails(nodeId) {
  var i, numNodes;
  numNodes = utg.nodes.length;
  for (i = 0; i < numNodes; i++) {
    if (utg.nodes[i].id == nodeId) {
      return utg.nodes[i];
    }
  }
  return "";
}
