from waitress import serve
import server  # Import your Flask app object

if __name__ == "__main__":
    serve(server.app, host='0.0.0.0', port=5000)
