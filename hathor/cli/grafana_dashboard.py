import json
import math
import os
from argparse import ArgumentParser, Namespace
from typing import Any, Callable, Dict, List, Optional

# Path of this file
dir_path = os.path.dirname(os.path.realpath(__file__))
# Path where json files are stored
json_path = os.path.join(dir_path, 'grafana')

# Name of Prometheus data source in Grafana
DATA_SOURCE = 'Prometheus - Localhost'
# Number of width columns in grafana
MAX_WIDTH = 24
# Height of the node label
NODE_TEXT_HEIGHT = 2

# Array of nodes that we are monitoring and will appear in the dashboard
NODES_FILE = os.path.join(json_path, 'nodes.json')
# Default dashboard json data
DASHBOARD_INITIAL_FILE = os.path.join(json_path, 'dashboard_initial.json')
# Default data for chart of type 'graph'
GRAPH_FILE = os.path.join(json_path, 'graph.json')
# Default data for chart of type 'percent'
PERCENT_FILE = os.path.join(json_path, 'percent.json')
# Default data for chart of text panel
TEXT_FILE = os.path.join(json_path, 'text.json')

# Folder where all charts files are stored
CHARTS_FOLDER = os.path.join(json_path, 'charts')

# All charts json
CHARTS_ARRAY = [
    'transactions', 'blocks', 'tx_rate', 'hash_rate_stacked', 'peers', 'cpu', 'cpu_load1m', 'cpu_load5m',
    'ram_percent', 'ram_line', 'network', 'cpu_line', 'load', 'disk'
]


def load_json(filename: str) -> Any:
    """ Load json file from disk and transform in dict

    :param filename: Name of json file
    :return: Json loaded
    """
    with open(filename, 'rb') as json_file:
        json_data = json_file.read()
        return json.loads(json_data)


def get_grafana_dashboard_json(title: str, data_source: str = DATA_SOURCE) -> str:
    """ Get data for each node and chart in the files and
        return a json ready to be imported in Grafana

        :param title: Title of the dashboard
        :type title: str

        :param data_source: Name of the prometheus data source
        :type data_source: str

        :return: Json ready to be imported in Grafana
        :rtype: str (json)
    """
    # Get common data of all dashboards
    data = get_initial_data(title)

    y = 0
    x = 0
    id_count = 1

    # Load nodes from file
    nodes: List[Dict['str', Any]] = load_json(NODES_FILE)

    chart_width_floor = math.floor(MAX_WIDTH / len(nodes))

    extra_width = MAX_WIDTH - chart_width_floor * len(nodes)

    def get_width(add_extra: bool) -> int:
        if add_extra:
            return chart_width_floor + 1
        else:
            return chart_width_floor

    for index, node in enumerate(nodes):
        # For each node I create a text panel with node name
        w = get_width(index + 1 <= extra_width)

        pos = {
            'h': NODE_TEXT_HEIGHT,
            'w': w,
            'x': x,
            'y': y,
        }
        text_data = get_text_panel_data(pos, node['name'])
        text_data['id'] = id_count
        id_count += 1
        data['panels'].append(text_data)

        x += w

    # Update y value with text panel height
    y += NODE_TEXT_HEIGHT

    for chart_file in CHARTS_ARRAY:
        # Load chart from file
        chart = load_json(os.path.join(CHARTS_FOLDER, '{}.json'.format(chart_file)))

        # For each chart I create a chart for each node
        x = 0
        w = 0

        # Get default chart data
        default_data = get_default_panel(chart['title'], data_source)
        # Get method I should call for this chart type
        method_to_call = get_method_to_call(chart['type'])

        for index, node in enumerate(nodes):
            # For each node I get the specific parameters and call the method for this chart
            kwargs = chart['params']
            kwargs['node'] = node['host']
            kwargs['job'] = node['job']

            w = get_width(index + 1 <= extra_width)

            kwargs['pos'] = {'h': chart['height'], 'w': w, 'x': x, 'y': y}
            chart_data = method_to_call(**kwargs)
            chart_data['id'] = id_count
            id_count += 1

            chart_data.update(default_data)
            data['panels'].append(chart_data)

            x += w

        # Update y with chart height
        y += chart['height']

    return json.dumps(data, indent=4)


def get_text_panel_data(pos: Dict[str, int], name: str) -> Dict[str, Any]:
    """ Loads text panel and fill with chart data
        Text panel is the chart that is only a text

        :param pos: Position and size of the chart in Grafana
        :type pos: Dict[str, int]

        :param name: Text to appear in the chart
        :type name: str

        :return: Data of the text panel
        :rtype: Dict
    """
    # Load data from file and update data with particular parameters
    data = load_json(TEXT_FILE)
    data['gridPos'] = pos
    data['content'] = data['content'].format(name)
    return data


def get_default_panel(title: str, data_source: str) -> Dict[str, str]:
    """ Gets data that is common for all panels

        :param title: Title of the chart
        :type title: str

        :param data_source: Data source of the data origin
        :type data_source: str

        :return: Default data of the chart
        :rtype: Dict[str,str]
    """
    data_panel = {
        'datasource': data_source,
        'title': title,
    }
    return data_panel


def get_percent_data(pos: Dict[str, int], query: str, node: str, job: str,
                     description: str) -> Dict[str, Any]:
    """ Gets data from percent chart

        :param pos: Position and size of the chart in Grafana
        :type pos: Dict[str, int]

        :param query: Expression from where we get the data
        :type query: str

        :param node: Url of node
        :type node: str

        :param job: Job in prometheus that generates this data
        :type job: str

        :param description: Description of this chart
        :type description: str

        :return: Data of the percent chart
        :rtype: Dict
    """
    # Format query string
    full_query = query.format(node, job)
    # Load data from file and update data with particular parameters
    data = load_json(PERCENT_FILE)
    data['description'] = description
    data['gridPos'] = pos
    data['targets'][0]['expr'] = full_query
    return data


def get_graph_data(pos: Dict[str, int], targets: List[Dict[str, Any]], node: str, job: str,
                   stack: bool = False, y_format: str = 'short', y_min: Optional[Any] = None,
                   y_max: Optional[Any] = None) -> Dict[str, Any]:
    """ Gets data from graph chart

        :param pos: Position and size of the chart in Grafana
        :type pos: Dict[str, int]

        :param targets: List of data parameters from where we get the data
        :type targets: list(Dict)

        :param node: Url of node
        :type node: str

        :param job: Job in prometheus that generates this data
        :type job: str

        :param stack: If data is stacked
        :type stack: bool

        :param y_format: Format of y axis (short, bytes, ...)
        :type y_format: str

        :param y_min: Min value of y axis
        :type y_min: str

        :param y_max: Max value of y axis
        :type y_max: str

        :return: Data of the graph chart
        :rtype: Dict
    """
    graph_targets = []
    for target in targets:
        # Format the expr string with parameters
        # Have to use copy of the dict, so I update only for this node
        t = target.copy()
        t['expr'] = t['expr'].format(node, job)
        graph_targets.append(t)

    # Load data from file and update data with particular parameters
    graph_data = load_json(GRAPH_FILE)
    graph_data['gridPos'] = pos
    graph_data['targets'] = graph_targets
    graph_data['stack'] = stack
    graph_data['yaxes'][0]['format'] = y_format
    graph_data['yaxes'][0]['min'] = y_min
    graph_data['yaxes'][0]['max'] = y_max
    return graph_data


def get_initial_data(title: str) -> Dict[str, Any]:
    """ Gets data common from all dashboards

        :param title: Title of the dashboard
        :type title: str

        :return: Default data of dashboard
        :rtype: Dict
    """
    # Load default data from file and add dashboard title
    data = load_json(DASHBOARD_INITIAL_FILE)
    data['title'] = title
    return data


def get_method_to_call(chart_type: str) -> Callable:
    """ Gets method to be called depending on the type of chart

        :param chart_type: Type of the chart I want the data
        :type chart_type: str

        :return: Method to be called
        :rtype: function
    """
    CHART_TO_METHOD: Dict[str, Callable] = {
        'graph': get_graph_data,
        'percent': get_percent_data,
    }
    return CHART_TO_METHOD[chart_type]


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('title', help='Title of the dashboard')
    parser.add_argument('--data_source', help='Name of data source')
    return parser


def execute(args: Namespace) -> None:
    kwargs = {'title': args.title}

    if args.data_source:
        kwargs['data_source'] = args.data_source

    print(get_grafana_dashboard_json(**kwargs))


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
