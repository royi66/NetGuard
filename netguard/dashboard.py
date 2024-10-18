from dash import Dash, dcc, html
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
def get_packet_distribution_by_direction():
    packets_collection = db[Collections.PACKETS]

    # Count IN and OUT packets
    in_count = packets_collection.count_documents({'direction': 'IN'})
    out_count = packets_collection.count_documents({'direction': 'OUT'})

    return {'IN': in_count, 'OUT': out_count}


# Fetch packet count per hour for the last 24 hours
def get_packet_count_by_hour():
    packets_collection = db[Collections.PACKETS]

    # Get current time and 24 hours ago
    now = datetime.now()
    one_day_ago = now - timedelta(hours=24)

    # Query MongoDB and group by hour
    pipeline = [
        {"$match": {"insertion_time": {"$gte": one_day_ago}}},
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
def create_direction_pie_chart():
    data = get_packet_distribution_by_direction()  # Fetch actual data from MongoDB
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
def create_packet_count_line_graph():
    hours, counts = get_packet_count_by_hour()  # Fetch packet counts by hour
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
        html.H1("", style={'textAlign': 'center'}),

        # Container Div for side-by-side layout of both charts
        html.Div([
            # First Chart: Packet Direction (50% width)
            html.Div(
                dcc.Graph(
                    figure=create_direction_pie_chart(),
                    style={'width': '45vw', 'height': '45vh'}  # Reduce size to fit both charts
                ),
                style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
            ),

            # Second Chart: Packet Count by Hour (50% width)
            html.Div(
                dcc.Graph(
                    figure=create_packet_count_line_graph(),
                    style={'width': '45vw', 'height': '45vh'}  # Reduce size to fit both charts
                ),
                style={'display': 'inline-block', 'vertical-align': 'top', 'width': '48%'}
            )
        ], style={'display': 'flex', 'justify-content': 'space-between'})
    ]
)


def run_dash_app():
    # TODO - change the port if refreshed
    app.run_server(debug=True, use_reloader=False, port=8050)


if __name__ == '__main__':
    run_dash_app()
