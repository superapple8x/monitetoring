use redis::AsyncCommands;
use serde_json;
use std::time::SystemTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Redis publishing...");
    
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
    let client = redis::Client::open(redis_url)?;
    let mut con = client.get_multiplexed_async_connection().await?;
    
    let test_message = serde_json::json!({
        "timestamp": SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "test": "FlowSummary publishing test",
        "active_flows_count": 42,
        "protocol_distribution": [
            {"protocol": 6, "flows_count": 8, "percentage_of_total_flows": 80.0},
            {"protocol": 17, "flows_count": 2, "percentage_of_total_flows": 20.0}
        ]
    });
    
    let serialized = serde_json::to_string(&test_message)?;
    println!("Publishing test message: {}", serialized);
    
    redis::cmd("PUBLISH")
        .arg("network_flows")
        .arg(serialized)
        .query_async::<_, ()>(&mut con)
        .await?;
    
    println!("Test message published successfully!");
    Ok(())
} 