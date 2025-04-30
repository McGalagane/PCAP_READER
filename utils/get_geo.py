import folium
from folium.plugins import MarkerCluster
import geoip2.database

class IPMapGenerator:
    def __init__(self, db_path='utils/GeoIP/GeoLite2-City.mmdb'):
        self.reader = geoip2.database.Reader(db_path)

    def get_location(self, ip):
        try:
            response = self.reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            city = response.city.name or "Unknown City"
            country = response.country.name or "Unknown Country"
            return {'ip': ip, 'lat': lat, 'lon': lon, 'city': city, 'country': country}
        except Exception:
            return None

    def generate_map(self, ip_list, zoom_start=5):
        world_map = folium.Map(location=[20, 0], zoom_start=zoom_start)
        marker_cluster = MarkerCluster().add_to(world_map)

        for ip in ip_list:
            location = self.get_location(ip)
            if location:
                if world_map.location == [20, 0]:
                    world_map.location = [location['lat'], location['lon']]
                folium.Marker(
                    location=[location['lat'], location['lon']],
                    popup=f"IP: {location['ip']}<br>{location['city']}, {location['country']}",
                    icon=folium.Icon(color='blue', icon='info-sign')
                ).add_to(marker_cluster)
        return world_map
