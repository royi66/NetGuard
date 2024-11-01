from dash import Dash, dcc, html, Input, Output
import plotly.graph_objs as go
from backend.handle_db import MongoDbClient
from consts import DBNames, Collections
from datetime import datetime, timedelta

# Connect to MongoDB
mongo_client = MongoDbClient()
db = mongo_client.client[DBNames.NET_GUARD_DB]

app = Dash(__name__)


def get_packet_distribution_by_direction(days_back):
    packets_collection = db[Collections.PACKETS]
    time_threshold = datetime.now() - timedelta(days=days_back)

    in_count = packets_collection.count_documents({'direction': 'IN', 'insertion_time': {'$gte': time_threshold}})
    out_count = packets_collection.count_documents({'direction': 'OUT', 'insertion_time': {'$gte': time_threshold}})

    return {'IN': in_count, 'OUT': out_count}

def get_packet_count_by_hour(days_back):
    packets_collection = db[Collections.PACKETS]
    now = datetime.now()
    time_threshold = now - timedelta(days=days_back)

    pipeline = [
        {"$match": {"insertion_time": {"$gte": time_threshold}}},
        {"$group": {
            "_id": {
                "hour": {"$hour": "$insertion_time"},
                "day": {"$dayOfMonth": "$insertion_time"}
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]

    results = list(packets_collection.aggregate(pipeline))
    hours = []
    counts = []

    for result in results:
        hour = result["_id"]["hour"]
        count = result["count"]
        hours.append(f"{hour}:00")
        counts.append(count)

    return hours, counts

def get_packet_distribution_by_rule_match(days_back):
    packets_collection = db[Collections.PACKETS]
    time_threshold = datetime.now() - timedelta(days=days_back)

    matched_count = packets_collection.count_documents({'matched_rule_id': {'$exists': True, '$ne': None}, 'insertion_time': {'$gte': time_threshold}})
    unmatched_count = packets_collection.count_documents({'$or': [{'matched_rule_id': None}, {'matched_rule_id': {'$exists': False}}], 'insertion_time': {'$gte': time_threshold}})

    return {'Matched': matched_count, 'Unmatched': unmatched_count}

def get_matched_rule_distribution(days_back):
    packets_collection = db[Collections.PACKETS]
    time_threshold = datetime.now() - timedelta(days=days_back)

    pipeline = [
        {"$match": {"matched_rule_id": {"$exists": True, "$ne": None}, "insertion_time": {"$gte": time_threshold}}},
        {"$group": {"_id": "$matched_rule_id", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]

    results = list(packets_collection.aggregate(pipeline))
    rule_ids = [str(result["_id"]) for result in results]
    counts = [result["count"] for result in results]

    return rule_ids, counts


def create_direction_pie_chart(days_back):
    data = get_packet_distribution_by_direction(days_back)
    fig = go.Figure(data=[go.Pie(labels=list(data.keys()), values=list(data.values()), hole=.3)])

    fig.update_layout(
        title="Packet Direction",
        paper_bgcolor='#1f1f1f',
        plot_bgcolor='#1f1f1f',
        font_color='white',
        margin=dict(l=20, r=20, t=40, b=20)
    )

    return fig


def create_packet_count_line_graph(days_back):
    hours, counts = get_packet_count_by_hour(days_back)
    fig = go.Figure(data=[go.Scatter(x=hours, y=counts, mode='lines+markers', line=dict(color='cyan'))])

    fig.update_layout(
        title="Amount of Packets per hour",
        xaxis_title="Time (Hour)",
        yaxis_title="Number of Packets",
        paper_bgcolor='#1f1f1f',
        plot_bgcolor='#1f1f1f',
        font_color='white',
        margin=dict(l=20, r=20, t=40, b=20)
    )

    return fig


def create_rule_match_pie_chart(days_back):
    data = get_packet_distribution_by_rule_match(days_back)
    fig = go.Figure(data=[go.Pie(labels=list(data.keys()), values=list(data.values()), hole=.3)])

    fig.update_layout(
        paper_bgcolor='#1f1f1f',
        plot_bgcolor='#1f1f1f',
        font_color='white',
        margin=dict(l=20, r=20, t=40, b=20)
    )

    return fig

def create_matched_rules_pie_chart(days_back):
    rule_ids, counts = get_matched_rule_distribution(days_back)
    fig = go.Figure(data=[go.Pie(labels=rule_ids, values=counts, hole=.3)])

    fig.update_layout(
        title="Distribution of Packets by Matched Rules",
        paper_bgcolor='#1f1f1f',
        plot_bgcolor='#1f1f1f',
        font_color='white',
        margin=dict(l=20, r=20, t=40, b=20)
    )

    return fig

app.layout = html.Div(
    style={'backgroundColor': '#1f1f1f', 'color': 'white'},
    children=[
        html.H1("Network Packet Analysis", style={'textAlign': 'center'}),

        html.Div([
            html.Label("Select Days Back:"),
            dcc.Dropdown(
                id='days-back-dropdown',
                options=[
                    {'label': '1 Day', 'value': 1},
                    {'label': '3 Days', 'value': 3},
                    {'label': '7 Days', 'value': 7},
                    {'label': '14 Days', 'value': 14}
                ],
                value=1,
                style={'width': '200px', 'backgroundColor': '#D3D3D3', 'color': 'black'}
            ),
        ], style={'textAlign': 'left', 'marginBottom': '20px', 'color': 'white'}),

        html.Div([
            # First Row of Charts
            html.Div([
                html.Div(
                    dcc.Graph(id='direction-pie-chart', style={'width': '40vw', 'height': '40vh'}),
                    style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
                ),
                html.Div(
                    dcc.Graph(id='packet-count-line-graph', style={'width': '40vw', 'height': '40vh'}),
                    style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
                )
            ], style={'display': 'flex', 'justify-content': 'space-between'}),

            # Second Row of Charts
            html.Div([
                html.Div(
                    dcc.Graph(id='rule-match-pie-chart', style={'width': '40vw', 'height': '40vh'}),
                    style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
                ),
                html.Div(
                    dcc.Graph(id='matched-rules-pie-chart', style={'width': '40vw', 'height': '40vh'}),
                    style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
                )
            ], style={'display': 'flex', 'justify-content': 'space-between'})
        ])
    ]

)

@app.callback(
    [Output('direction-pie-chart', 'figure'),
     Output('packet-count-line-graph', 'figure'),
     Output('rule-match-pie-chart', 'figure'),
     Output('matched-rules-pie-chart', 'figure')],
    [Input('days-back-dropdown', 'value')]
)
def update_charts(days_back):
    pie_chart = create_direction_pie_chart(days_back)
    line_graph = create_packet_count_line_graph(days_back)
    rule_match_chart = create_rule_match_pie_chart(days_back)
    matched_rules_chart = create_matched_rules_pie_chart(days_back)
    return pie_chart, line_graph, rule_match_chart, matched_rules_chart

def run_dash_app():
    app.run_server(debug=True, use_reloader=False, port=8050)

if __name__ == '__main__':
    run_dash_app()
