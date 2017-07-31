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
  utg_details.innerHTML = "<h2>Overall Results</h2>\n" + getOverallResult();
}

function getOverallResult() {
  return utg.overall;
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
