Splunk.Module.sitehopping_without_single_node = $.klass(Splunk.Module.DispatchingModule, {
    initialize: function($super, container) {
        $super(container);
	this.myParam = this.getParam("myParam");
        this.resultsContainer = this.container;
    },
	
    onJobDone: function(event) {
        this.getResults();
    },

    getResultParams: function($super) {
        var params = $super();
        var context = this.getContext();
        var search = context.get("search");
        var sid = search.job.getSearchId();

        if (!sid) this.logger.error(this.moduleType, "Assertion Failed.");

        params.sid = sid;
        return params;
    },

    renderResults: function($super, results) {
        if(!results) {
            this.resultsContainer.html("No content available.");
            return;
        }
        console.debug('Get data');
        if (!d3.select("div.sitehopping_without_single_node_malware > svg").empty()) {
            d3.select("div.sitehopping_without_single_node_malware svg").remove();
        }
        var node,
			link,
			root = results,
			width = 600,
			height = 800;

		root.fixed = true;
		root.x = 0;
		root.y = 0;

	    var force = d3.layout.force()
			.on("tick", tick)
			.charge(function(d) {return -10;})
			.linkDistance(function(d) {return 20})
			.size([width, height]);

		var vis = d3.select("div.sitehopping_without_single_node_malware").append("svg")
			.attr("width", width)
			.attr("height", height);
		update();
		function update() {
			var nodes = root.nodes,
				links = root.links;
		force
			.nodes(nodes)
			.links(links)
		    .start();

		var path = vis.append("svg:g").selectAll("path")
		    .data(force.links())
		  .enter().append("svg:path")
		    .attr("class", function(d) { return "link " + d.type; })
		    .attr("marker-end", function(d) { return "url(#" + d.type + ")"; });


  		link = vis.selectAll("line.link")
	    	.data(links, function(d) { return d.target.id; });

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
		    .attr("r", function(d) { return d.children ? 7.5 : d.size / 100; });

		// Enter any new nodes.
		node.enter().append("circle")
		    .attr("class", "node")
		    .attr("cx", function(d) { return d.x; })
		    .attr("cy", function(d) { return d.y; })
		    .attr("r", function(d) { return d.children ? 7.5 : d.size / 100; })
		    .style("fill", color)
		    .on("click", click)
		    .call(force.drag);
		node.append("title")
			.text(function(d) {
          var d = this.__data__;
          var description;
          if (d.group == 1) {
              description = 'Landding site : ';
          }
          else if (d.group == 2) {
              description = 'Hopping site : ';
          }
          else if (d.group == 3) {
              description = 'Single Link : ';
          }
          else if (d.group == 4) {
              description = 'malware md5 : ';
          }
          else
              description = 'Undefined : ';
          var append = d.country ? ' location : ' + d.country : '';

        return description + d.name + append;
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
        return "#FF0000";
    }
    else
        return "#EE0000";
//  return d._group ? "#00ee00" : d.children ? "#000000" : "#0000ee";
}
function click(d) {
}
/*

        var w = 1400,
            h = 900;
        var root = results;
        root.fix = true;
        root.x = w / 2;
        root.y = h / 2;
        update();

        function update() {
            var nodes = root.nodes;
            var links = root.links;


            var force = d3.layout.force()
                .nodes(nodes)
                .links(links)
                .size([w, h])
                .linkDistance(45)
                .charge(-25)
                .on("tick", tick)
                .start();

            var svg = d3.select("div.sitehoppint_malware").append("svg:svg")
                .attr("width", w)
                .attr("height", h);

            var path = svg.append("svg:g").selectAll("path")
                .data(force.links())
              .enter().append("svg:path")
                .attr("class", function(d) { return "link " + d.type; })
                .attr("marker-end", function(d) { return "url(#" + d.type + ")"; });

            var circle = svg.append("svg:g").selectAll("circle")
                .data(force.nodes())
              .enter().append("svg:circle")
                .attr("r", 6)
                .call(force.drag)
                .style("fill", color);
            circle.append("title")
                .text(function(d) {return d.name});
                
            function tick() {
                path.attr("d", function(d) {
                        var dx = d.target.x - d.source.x,
                        dy = d.target.y - d.source.y,
                        dr = Math.sqrt(dx * dx + dy * dy);
                        return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
                        });

                circle.attr("transform", function(d) {
                        return "translate(" + d.x + "," + d.y + ")";
                        });
            }
            function color(d) {
                if (d.group == 1)
                    return "red";
                if (d.group == 2)
                    return "blue";
                if (d.group == 3)
                    return "silver";
                if (d.group == 4)
                    return "black";
                else
                    return "yellow";
            }
        }
*/
	}
});
