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
      shapeProperties: {
        useBorderWithImage: true
      },

      borderWidth: 0,
      borderWidthSelected: 5,

      color: {
        border: '#FFFFFF',
        background: '#FFFFFF',

        highlight: {
          border: '#0000FF',
          background: '#0000FF',
        }
      },

      font: {
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
      if (network.isCluster(node)) {
        utg_details.innerHTML = getClusterDetails(node);
      }
      else {
        utg_details.innerHTML = getNodeDetails(node);
      }
    }
    else if (params.edges.length > 0) {
      edge = params.edges[0];
      baseEdge = network.clustering.getBaseEdge(edge)
      if (baseEdge == null || baseEdge == edge) {
        utg_details.innerHTML = getEdgeDetails(edge);
      } else {
        utg_details.innerHTML = getEdgeDetails(baseEdge);
      }
    }
  });
}

function showOverall() {
  var utg_details = document.getElementById('utg_details');
  utg_details.innerHTML = getOverallResult();
}

function getOverallResult() {
  var overallInfo = "<hr />";
  overallInfo += "<table class=\"table\">\n"

  overallInfo += "<tr class=\"active\"><th colspan=\"2\"><h4>App information</h4></th></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Package</th><td class=\"col-md-4\">" + utg.app_package + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">SHA-256</th><td class=\"col-md-4\">" + utg.app_sha256 + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Main activity</th><td class=\"col-md-4\">" + utg.app_main_activity + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># activities</th><td class=\"col-md-4\">" + utg.app_num_total_activities + "</td></tr>\n";

  overallInfo += "<tr class=\"active\"><th colspan=\"2\"><h4>Device information</h4></th></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Device serial</th><td class=\"col-md-4\">" + utg.device_serial + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Model number</th><td class=\"col-md-4\">" + utg.device_model_number + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">SDK version</th><td class=\"col-md-4\">" + utg.device_sdk_version + "</td></tr>\n";

  overallInfo += "<tr class=\"active\"><th colspan=\"2\"><h4>DroidBot result</h4></th></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Test date</th><td class=\"col-md-4\">" + utg.test_date + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\">Time spent (s)</th><td class=\"col-md-4\">" + utg.time_spent + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># input events</th><td class=\"col-md-4\">" + utg.num_input_events + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># UTG states</th><td class=\"col-md-4\">" + utg.num_nodes + "</td></tr>\n";
  overallInfo += "<tr><th class=\"col-md-1\"># UTG edges</th><td class=\"col-md-4\">" + utg.num_edges + "</td></tr>\n";
  activity_coverage = 100 * utg.num_reached_activities / utg.app_num_total_activities;
  overallInfo += "<tr><th class=\"col-md-1\">Activity_coverage</th><td class=\"col-md-4 progress\"><div class=\"progress-bar\" role=\"progressbar\" aria-valuenow=\"" + utg.num_reached_activities + "\" aria-valuemin=\"0\" aria-valuemax=\"" + utg.app_num_total_activities + "\" style=\"width: " + activity_coverage + "%;\">" + utg.num_reached_activities + "/" + utg.app_num_total_activities + "</div></td></tr>\n";

  overallInfo += "</table>";
  return overallInfo;
}

function getEdgeDetails(edgeId) {
  var selectedEdge = getEdge(edgeId);
  edgeInfo = "<h2>Transition Details</h2><hr/>\n";
  fromState = getNode(selectedEdge.from);
  toState = getNode(selectedEdge.to);
  edgeInfo += "<img class=\"col-md-5\" src=\"" + fromState.image + "\">\n"
  edgeInfo += "<div class=\"col-md-2 text-center\">TO</div>\n"
  edgeInfo += "<img class=\"col-md-5\" src=\"" + toState.image + "\">\n"
  edgeInfo += "<table class=\"table table-striped\">\n"
  edgeInfo += "<tr class=\"active\"><th colspan=\"4\"><h4>Events</h4></th></tr>\n";

  var i;
  edgeInfo += "<tr><th>id</th><th>type</th><th>view</th><th>event_str</th></tr>\n"
  for (i = 0; i < selectedEdge.events.length; i++) {
    event = selectedEdge.events[i];
    eventStr = event.event_str;
    var viewImg = "";
    if (event.view_images != null) {
      var j;
      for (j = 0; j < event.view_images.length; j++) {
        viewImg += "<img class=\"viewImg\" src=\"" + event.view_images[j] + "\">\n"
      }
    }
    edgeInfo += "<tr><td>" + event.event_id + "</td><td>" + event.event_type + "</td><td>" + viewImg + "</td><td>" + event.event_str + "</td></tr>"
  }
  edgeInfo += "</table>\n"
  return edgeInfo;
}

function getNodeDetails(nodeId) {
  var selectedNode = getNode(nodeId);
  stateInfo = "<h2>State Details</h2><hr/>\n";
  stateInfo += "<img class=\"col-md-5\" src=\"" + selectedNode.image + "\">"
  stateInfo += "<div class=\"col-md-7\">" + selectedNode.title + "</div>";
  return stateInfo;
}

function getClusterDetails(clusterId) {
  clusterInfo = "<h2>Cluster Details</h2><hr/>\n";
  var nodeIds = network.getNodesInCluster(clusterId);
  for (var i = 0; i < nodeIds.length; i++) {
    var selectedNode = getNode(nodeIds[i]);
    clusterInfo += "<div class=\"row\">\n"
    clusterInfo += "<img class=\"col-md-5\" src=\"" + selectedNode.image + "\">"
    clusterInfo += "<div class=\"col-md-7\">" + selectedNode.title + "</div>";
    clusterInfo += "</div><br />"
  }
  return clusterInfo;
}

function getEdge(edgeId) {
  var i, numEdges;
  numEdges = utg.edges.length;
  for (i = 0; i < numEdges; i++) {
    if (utg.edges[i].id == edgeId) {
      return utg.edges[i];
    }
  }
  console.log("cannot find edge: " + edgeId);
}

function getNode(nodeId) {
  var i, numNodes;
  numNodes = utg.nodes.length;
  for (i = 0; i < numNodes; i++) {
    if (utg.nodes[i].id == nodeId) {
      return utg.nodes[i];
    }
  }
  console.log("cannot find node: " + nodeId);
}

function showAbout() {
  var utg_details = document.getElementById('utg_details');
  utg_details.innerHTML = getAboutInfo();
}

function getAboutInfo() {
  var aboutInfo = "<hr />";
  aboutInfo += "<h2>About</h2>\n"
  aboutInfo += "<p>This report is generated using <a href=\"https://github.com/honeynet/droidbot\">DroidBot</a>.</p>\n";
  aboutInfo += "<p>Please find copyright information in the project page.</p>";
  return aboutInfo;
}

function searchUTG() {
  var searchKeyword = document.getElementById("utgSearchBar").value.toUpperCase();
  if (searchKeyword == null || searchKeyword == "") {
    network.unselectAll()
  } else {
    var i, numNodes;
    nodes = utg.nodes;
    numNodes = nodes.length;
    selectedNodes = []
    for (i = 0; i < numNodes; i++) {
      if (nodes[i].content.toUpperCase().indexOf(searchKeyword) > -1) {
        selectedNodes.push(nodes[i].id)
      }
    }
    network.unselectAll()
    // console.log("Selecting: " + selectedNodes)
    network.selectNodes(selectedNodes, false)
  }
}

function clusterStructures() {
  network.setData(utg)
  var structures = [];

  for (var i = 0; i < utg.nodes.length; i++) {
    node = utg.nodes[i]
    if (structures.indexOf(node.structure_str) < 0) {
      structures.push(node.structure_str)
    }
  }

  var clusterOptionsByData;
  for (var i = 0; i < structures.length; i++) {
      var structure = structures[i];
      clusterOptionsByData = {
          joinCondition: function (childOptions) {
              return childOptions.structure_str == structure;
          },
          processProperties: function (clusterOptions, childNodes, childEdges) {
              clusterOptions.title = childNodes[0].title;
              clusterOptions.state_str = childNodes[0].state_str;
              clusterOptions.label = childNodes[0].label;
              clusterOptions.image = childNodes[0].image;
              return clusterOptions;
          },
          clusterNodeProperties: {id: 'structure:' + structure, shape: 'image'}
      };
      network.cluster(clusterOptionsByData);
  }
}

function clusterActivities() {
  network.setData(utg)
  var activities = [];

  for (var i = 0; i < utg.nodes.length; i++) {
    node = utg.nodes[i]
    if (activities.indexOf(node.activity) < 0) {
      activities.push(node.activity)
    }
  }

  var clusterOptionsByData;
  for (var i = 0; i < activities.length; i++) {
      var activity = activities[i];
      clusterOptionsByData = {
          joinCondition: function (childOptions) {
              return childOptions.activity == activity;
          },
          processProperties: function (clusterOptions, childNodes, childEdges) {
              clusterOptions.title = childNodes[0].title;
              clusterOptions.state_str = childNodes[0].state_str;
              clusterOptions.label = childNodes[0].label;
              clusterOptions.image = childNodes[0].image;
              return clusterOptions;
          },
          clusterNodeProperties: {id: 'activity:' + activity, shape: 'image'}
      };
      network.cluster(clusterOptionsByData);
  }
}

function showOriginalUTG() {
  network.setData(utg)
  network.redraw()
}
