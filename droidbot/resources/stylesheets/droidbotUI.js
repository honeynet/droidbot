var network = null;
// Called when the Visualization API is loaded.
function draw() {
  // create a network
  var container = document.getElementById('utg_div');

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
  network = new vis.Network(container, utg, options);
}
