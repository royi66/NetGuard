from dash import Dash, dcc, html, Input, Output
import plotly.graph_objs as go
from pymongo import MongoClient
from handle_db import MongoDbClient
from consts import DBNames, Collections
from datetime import datetime, timedelta

# Connect to MongoDB
mongo_client = MongoDbClient()
db = mongo_client.client[DBNames.NET_GUARD_DB]

app = Dash(__name__)

# Fetch packet direction data from MongoDB
def get_packet_distribution_by_direction(days_back):
    packets_collection = db[Collections.PACKETS]
    time_threshold = datetime.now() - timedelta(days=days_back)

    # Count IN and OUT packets from the specified time period
    in_count = packets_collection.count_documents({'direction': 'IN', 'insertion_time': {'$gte': time_threshold}})
    out_count = packets_collection.count_documents({'direction': 'OUT', 'insertion_time': {'$gte': time_threshold}})

    return {'IN': in_count, 'OUT': out_count}

# Fetch packet count per hour for the specified number of days back
def get_packet_count_by_hour(days_back):
    packets_collection = db[Collections.PACKETS]

    # Get the current time and the time threshold based on days back
    now = datetime.now()
    time_threshold = now - timedelta(days=days_back)

    # Query MongoDB and group by hour
    pipeline = [
        {"$match": {"insertion_time": {"$gte": time_threshold}}},
        {"$group": {
            "_id": {
                "hour": {"$hour": "$insertion_time"},
                "day": {"$dayOfMonth": "$insertion_time"}
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}  # Sort by time
    ]

    results = list(packets_collection.aggregate(pipeline))

    # Prepare the data
    hours = []
    counts = []

    for result in results:
        hour = result["_id"]["hour"]
        count = result["count"]
        hours.append(f"{hour}:00")
        counts.append(count)

    return hours, counts

# Create the packet direction pie chart
def create_direction_pie_chart(days_back):
    data = get_packet_distribution_by_direction(days_back)  # Fetch actual data from MongoDB
    fig = go.Figure(data=[go.Pie(labels=list(data.keys()), values=list(data.values()), hole=.3)])

    # Set dark mode colors for the chart
    fig.update_layout(
        paper_bgcolor='#1f1f1f',
        plot_bgcolor='#1f1f1f',
        font_color='white',
        margin=dict(l=20, r=20, t=40, b=20)  # Reduce margins for compact size
    )

    return fig

# Create the packet count per hour line graph
def create_packet_count_line_graph(days_back):
    hours, counts = get_packet_count_by_hour(days_back)  # Fetch packet counts by hour
    fig = go.Figure(
        data=[go.Scatter(x=hours, y=counts, mode='lines+markers', line=dict(color='cyan'))]
    )

    fig.update_layout(
        title="Packets per Hour (Last 24 Hours)",
        xaxis_title="Time (Hour)",
        yaxis_title="Number of Packets",
        paper_bgcolor='#1f1f1f',
        plot_bgcolor='#1f1f1f',
        font_color='white',
        margin=dict(l=20, r=20, t=40, b=20)  # Reduce margins for compact size
    )

    return fig

# Set up the layout for the Dash app with both charts
app.layout = html.Div(
    style={'backgroundColor': '#1f1f1f', 'color': 'white'},
    children=[
        html.H1("Network Packet Analysis", style={'textAlign': 'center'}),

        # Dropdown to select the number of days back for the query
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
                value=1,  # Default selection
                style={'width': '200px', 'backgroundColor': '#D3D3D3', 'color': 'black'}
            ),
        ], style={'textAlign': 'left', 'marginBottom': '20px', 'color': 'white'}),

        # Container Div for side-by-side layout of both charts
        html.Div([
            # First Chart: Packet Direction (45% width)
            html.Div(
                dcc.Graph(
                    id='direction-pie-chart',
                    style={'width': '40vw', 'height': '40vh'}  # Reduce size
                ),
                style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
            ),

            # Second Chart: Packet Count by Hour (50% width)
            html.Div(
                dcc.Graph(
                    id='packet-count-line-graph',
                    style={'width': '45vw', 'height': '40vh'}  # Reduce size
                ),
                style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
            )
        ], style={'display': 'flex', 'justify-content': 'space-between'})
    ]
)

# Callback to update the charts based on the selected days back
@app.callback(
    [Output('direction-pie-chart', 'figure'), Output('packet-count-line-graph', 'figure')],
    [Input('days-back-dropdown', 'value')]
)
def update_charts(days_back):
    # Generate updated charts based on the selected number of days back
    pie_chart = create_direction_pie_chart(days_back)
    line_graph = create_packet_count_line_graph(days_back)
    return pie_chart, line_graph

def run_dash_app():
    app.run_server(debug=True, use_reloader=False, port=8050)

if __name__ == '__main__':
    run_dash_app()
