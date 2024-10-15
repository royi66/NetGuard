from dash import Dash, dcc, html
import plotly.graph_objs as go

app = Dash(__name__)

# Create the packet direction pie chart
def create_direction_pie_chart():
    data = {
        'IN': 150,
        'OUT': 100
    }
    fig = go.Figure(data=[go.Pie(labels=list(data.keys()), values=list(data.values()), hole=.3)])
    return fig

# Set up the layout for the Dash app
app.layout = html.Div([
    html.H1("Packet Direction Dashboard"),
    dcc.Graph(figure=create_direction_pie_chart())
])

def run_dash_app():
    app.run_server(debug=True, use_reloader=False, port=8050)

if __name__ == '__main__':
    run_dash_app()
