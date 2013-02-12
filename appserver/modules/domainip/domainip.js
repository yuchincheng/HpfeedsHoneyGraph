Splunk.Module.domainip = $.klass(Splunk.Module.DispatchingModule, {
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
        if (!d3.select("div.domainip_malware > svg").empty()) {
            d3.select("div.domainip_malware svg").remove();
        }

		var node,
			link,
			root = results,
			width = 1000,
			height =1000;

		root.fixed = true;
		root.x = width / 2;
		root.y = height / 2;

	    var force = d3.layout.force()
			.on("tick", tick)
			.charge(function(d) {return -30;})
			.linkDistance(function(d) {return 35})
			.size([width, height]);

		var vis = d3.select("div.domainip_malware").append("svg")
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
		    .attr("r", size);
//		    .attr("r", function(d) { return d.size / 100; });

		// Enter any new nodes.
		node.enter().append("circle")
		    .attr("class", "node")
		    .attr("cx", function(d) { return d.x; })
		    .attr("cy", function(d) { return d.y; })
//		    .attr("r", function(d) { return d.size / 100; })
		    .attr("r", size)
		    .style("fill", color)
		    .on("click", click)
		    .call(force.drag);
		node.append("title")
			.text(function(d) {
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
          var append = d.country ? ' location : ' + d.country : '';

        return description + d.name + '\n' + append;
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
	return "#0000FF";
         # return "#C00000";
    }
    else if (d.group == 4) {
//        return "#6699CC";
        return "#6699CC";
    }
    else if (d.group == 5) {
        return "#C00000";
    }
    else
        return "#EE0000";
//  return d._group ? "#00ee00" : d.children ? "#000000" : "#0000ee";
}
function size(d) {
    if (d.group == 0) {
        return 3;
    }
    else if (d.group == 1) {
        return 3.5;
    }
    else if (d.group == 2) {
        return 4.5;
    }
    else if (d.group == 3) {
        return 5.5;
    }
    else if (d.group == 4) {
        return 4.5;
//        return 6;
    }
    else if (d.group == 5) {
//        return 6.5;
        return 4.5;
    }
    else
        return 10;

}
function click(d) {
}

	}
});
