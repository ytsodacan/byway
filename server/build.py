import json
import random

def get_precise_land_coordinate():
    # Defined land zones mapped tightly to real peninsula coastlines
    # (lat_min, lat_max, lon_min, lon_max) * 1,000,000
    land_zones = [
        # 1. Soldiers Point & Salamander Shores (Northwest peninsula)
        (-32725000, -32710000, 152060000, 152085000),
        # 2. Tanilba Bay & Lemon Tree Passage (Far West peninsula)
        (-32745000, -32725000, 151950000, 152050000),
        # 3. Bobs Farm & Salt Ash Inland Highway (West)
        (-32780000, -32745000, 151980000, 152100000),
        # 4. Anna Bay, One Mile & Birubi Beach Inland (South Coast land)
        (-32790000, -32755000, 152080000, 152150000),
        # 5. Salamander Bay, Corlette & Taylors Beach (Center Land)
        (-32745000, -32725000, 152080000, 152140000),
        # 6. Nelson Bay & Little Beach (North East)
        (-32730000, -32715000, 152130000, 152165000),
        # 7. Shoal Bay & Nelson Head Inland (North East tip)
        (-32730000, -32718000, 152160000, 152185000),
        # 8. Fingal Bay Inland (East coast - avoiding ocean)
        (-32750000, -32735000, 152165000, 152185000)
    ]
    
    zone = random.choice(land_zones)
    lat = random.randint(zone[0], zone[1])
    lon = random.randint(zone[2], zone[3])
    return lat, lon

# 1. Generate 2,000 Wazers across all land zones
wazers = []
session_start = 910000
for i in range(2000):
    lat, lon = get_precise_land_coordinate()
    
    wazers.append({
        "mode": "DELETE_IF_NOT_UPDATE",
        "id": {
            "session_id": session_start + i
        },
        "gps_sample": {
            "position": {
                "lon_times_1000000": lon,
                "lat_times_1000000": lat
            },
            "azymuth": random.choice([0, 45, 90, 135, 180, 225, 270, 315]),
            "speed_millis_per_second": random.choice([0, 1500, 4000, 8000, 15000])
        },
        "mood": i % 12,
        "addon": "NONE",
        "rank": random.randint(0, 5),
        "points": random.randint(100, 20000),
        "join_date_sec": 1700000000,
        "capabilities": 7,
        "can_ping": False,
        "can_private_message": False
    })

# 2. Generate MASSIVE 15,000 Potholes covering every single town
alerts = []
alert_start = 990001
for j in range(15000):
    lat, lon = get_precise_land_coordinate()
    
    alert = {
        "_age_sec": random.randint(60, 10800),
        "realtime_alert": {
            "id": alert_start + j,
            "alert_info": {
                "type": "HAZARD",
                "sub_type": "HAZARD_ON_ROAD_POT_HOLE",
                "position": {
                    "lon_times_1000000": lon,
                    "lat_times_1000000": lat
                },
                "segment_direction_id": {
                    "from_node": 176677667 + (j % 5000),
                    "to_node": 163356063 + (j % 5000)
                },
                "seg_direction": random.choice(["FORWARDS", "BACKWARDS"]),
                "azymuth": random.choice([0, 90, 180, 270]),
                "on_route": False,
                "priority": 1000,
                "alert_details": {
                    "hazard_on_road": {
                        "type": "HAZARD_POTHOLE"
                    }
                }
            },
            "alert_reporting_info": {
                "primary_alert_id": -1,
                "kind": "PRIMARY",
                "report_time": 0,
                "reporter_username": f"PotholeHunter_{(j % 500) + 1}",
                "current_user_is_reporter": False,
                "report_image_id": "",
                "alert_address": {
                    "location_near_by_report": "Severe pothole hazard",
                    "street": f"Peninsula Way {(j % 200) + 1}",
                    "city": random.choice([
                        "Soldiers Point", "Tanilba Bay", "Lemon Tree Passage", 
                        "Bobs Farm", "Anna Bay", "Salamander Bay", 
                        "Nelson Bay", "Shoal Bay", "Fingal Bay"
                    ])
                },
                "thumbs_up_count": random.randint(1, 300),
                "current_user_thumbed_up": False,
                "seconds_to_report": -1,
                "beepInfo": {},
                "chatInfo": {
                    "private": False
                }
            },
            "alert_uuid": f"00000000-0000-4000-8000-{j+1:012d}"
        }
    }
    alerts.append(alert)

world_data = {
    "wazers": wazers,
    "alerts": alerts
}

filename = "world.json"
with open(filename, "w", encoding="utf-8") as f:
    json.dump(world_data, f, indent=2)

print(f"Generated {filename} with {len(wazers)} Wazers and {len(alerts)} potholes cleanly on land across all towns!")
