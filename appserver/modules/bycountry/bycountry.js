Splunk.Module.bycountry = $.klass(Splunk.Module.DispatchingModule, {
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
        if (!d3.select("div.bycountry_malware > svg").empty()) {
            d3.select("div.bycountry_malware svg").remove();
        }

		var node,
			link,
			root = results,
			width = 1000,
			height = 600;

		root.fixed = true;
		root.x = width / 2;
		root.y = height / 2;

	    var force = d3.layout.force()
			.on("tick", tick)
			.charge(function(d) {return -30;})
			.linkDistance(function(d) {return 35})
			.size([width, height]);

		var vis = d3.select("div.bycountry_malware").append("svg")
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
              description = 'malicious pages host on : ' + d.name;
          }
          else if (d.group == 2) {
              description = 'malware md5 : ';
          }
          else if (d.group == 3) {
              description = 'malicious hostname : ';
          }
          else if (d.group == 4) {
              description = 'Relative IP : ';
          }
          else
              description = 'Undefined : ';
          if (d.info_lable) {
              for (var x in d.info_lable) {
                  description = description + '\n' + d.info_lable[x] ;
              }
              return description;

          }
          else
              return description + d.name;
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
        return "#6699CC";
    }
    else
        return "#EE0000";
//  return d._group ? "#00ee00" : d.children ? "#000000" : "#0000ee";
}
function click(d) {
}

	}
});
