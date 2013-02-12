document.write('<script type="text/javascript" src="http://code.jquery.com/jquery-1.6.2.min.js"></script>');
document.write('<script type="text/javascript" src="/static/app/HpfeedsHoneyGraph/jquery.tipsy.js"></script>');    

var width = 1000,
    height = 900,
    node,
    link,
    root;

var force = d3.layout.force()
    .on("tick", tick)
    .charge(function(d) { return d._children ? -d.size / 70 : -30; })
    .linkDistance(function(d) { return d._children ? 70 : 30; })
    .size([width, height]);

var vis = d3.select("#chart").append("svg")
    .attr("width", width)
    .attr("height", height);


d3.json("/static/app/HpfeedsHoneyGraph/newest_flare.json", function(json) {
  root = json;
  root.fixed = true;
  root.x = width / 2;
  root.y = height / 2;
  update();
});

function update() {
  var nodes = root.nodes,
      links = root.links;
  // Restart the force layout.
  force
      .nodes(nodes)
      .links(links)
      .start();

var svg = d3.select("body").append("svg:svg")
    .attr("width", width)
    .attr("height", height);

var path = svg.append("svg:g").selectAll("path")
    .data(force.links())
  .enter().append("svg:path")
    .attr("class", function(d) { return "link " + d.type; })
    .attr("marker-end", function(d) { return "url(#" + d.type + ")"; });


  // Update the links…
  link = vis.selectAll("line.link")
      .data(links, function(d) { return d.target.id; });

  // Enter any new links.
  link.enter().insert("line", ".node")
      .attr("class", "link")
      .attr("x1", function(d) { return d.source.x; })
      .attr("y1", function(d) { return d.source.y; })
      .attr("x2", function(d) { return d.target.x; })
      .attr("y2", function(d) { return d.target.y; });

  // Exit any old links.
  link.exit().remove();

  // Update the nodes…
  node = vis.selectAll("circle.node")
      .data(nodes, function(d) { return d.id; })
      .style("fill", color);


  node.transition()
      .attr("r", function(d) { return d.children ? 4.5 : d.size / 100; });

  // Enter any new nodes.
  node.enter().append("circle")
      .attr("class", "node")
      .attr("cx", function(d) { return d.x; })
      .attr("cy", function(d) { return d.y; })
      .attr("r", function(d) { return d.children ? 4.5 : d.size / 100; })
      .style("fill", color)
      .on("click", click)
      .call(force.drag);

  $('svg circle').tipsy({ 
    gravity: 'w',
    html: true, 
    title: function() {
      var d = this.__data__;
      var description;
      if (d.group == 1) {
          description = 'malware md5 = ';
      }
      else if (d.group == 2) {
          description = 'malicous hostname : ';
      }
      else if (d.group == 3) {
          description = 'resloved IP : ';
      }
      else if (d.group == 4) {
          description = 'Passive DNS lookup : ';
      }
      else if (d.group == 5) {
          description = 'resloved IP from Passive DNS lookup : ';
      }
      else if (d.group == 0) {
          description = 'Samples analysis by ';
      }
      else 
          description = 'Undefined : ';

        return '<div class="popout"><span>' + description + d.name + '</span></div>';
    }
  });

     
  // Exit any old nodes.
  node.exit().remove();
}

function tick() {
  link.attr("x1", function(d) { return d.source.x; })
      .attr("y1", function(d) { return d.source.y; })
      .attr("x2", function(d) { return d.target.x; })
      .attr("y2", function(d) { return d.target.y; });

  node.attr("cx", function(d) { return d.x; })
      .attr("cy", function(d) { return d.y; });
}

// Color leaf nodes orange, and packages white or blue.
function color(d) {
    if (d.group == 0) {
        return "#CC33CC";
    }
    else if (d.group == 1) {
        return "#00EECC";
    }
    else if (d.group == 2) {
        return "#000000";
    }
    else if (d.group == 3) {
        return "#0000EE";
    }
    else if (d.group == 4) {
        return "#6699CC";
    }
    else
        return "#EE0000";
//  return d._group ? "#00ee00" : d.children ? "#000000" : "#0000ee";
}

// Toggle children on click.
function click(d) {
  if (d.children) {
    d._children = d.children;
    d.children = null;
  } else {
    d.children = d._children;
    d._children = null;
  }
  update();
}

// Returns a list of all nodes under the root.
function flatten(root) {
  var nodes = [], i = 0;

  function recurse(node) {
    if (node.children) node.size = node.children.reduce(function(p, v) { return p + recurse(v); }, 0);
    if (!node.id) node.id = ++i;
    nodes.push(node);
    return node.size;
  }

  root.size = recurse(root);
  return nodes;
}
