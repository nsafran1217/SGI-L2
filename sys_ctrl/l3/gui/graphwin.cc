/*
 * sys_ctrl/l3/gui/graphwin.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/graphwin.cc
 *
 * "Performance Graphs": a bar chart of random values (a demo; its button is
 * hidden in the main window).
 */

#include <stdlib.h>
#include <FL/Fl_Chart.H>
#include "l2gui.h"
#include "ui/graphwin.cxx"

graph_def graph_data[10] = {
  { "Sys", 14.0, 4 },
  { "Knl", 3.0, 1 },
  { "Usr", 9.0, 2 },
  { "Gfx", 1.0, 3 },
  { "AAA", 1.0, 5 },
  { "BBB", 20.0, 6 },
  { "CCC", 1.0, 40 },
  { "DDD", 1.0, 60 },
  { "EEE", 1.0, 80 },
  { "FFF", 1.0, 100 },
};
int graph_data_len = sizeof(graph_data) / sizeof(graph_data[0]);
Fl_Chart *graph;

int graphwin_init(void)
{
  int i;

  graphwin = make_graphwin();
  l2gui_add(graphwin);
  graph = new Fl_Chart(10, 10, 300, 180);
  graph->type(FL_BAR_CHART);
  graph->autosize(1);
  graph->bounds(0.0, 25.0);
  graph_area->add(graph);
  for (i = 0; i < graph_data_len; i++) {
    graph_data[i].value = rand() * 25.0 / 2147483648.0;
    graph->insert(i + 1, graph_data[i].value, graph_data[i].name, graph_data[i].color);
  }
  return 0;
}

void graphwin_update_data(void *data)
{
  int i;

  if (!graphwin->visible_r())
    return;
  for (i = 0; i < graph_data_len; i++) {
    graph_data[i].value = rand() * 25.0 / 2147483648.0;
    graph->replace(i + 1, graph_data[i].value, graph_data[i].name, graph_data[i].color);
  }
  graph->redraw();
  Fl::add_timeout(0.25, graphwin_update_data, NULL);
}

void graphwin_show(void)
{
  Fl::add_timeout(0.25, graphwin_update_data, NULL);
  l2gui_show(graphwin);
}

void graphwin_hide(void)
{
  graphwin->hide();
}
