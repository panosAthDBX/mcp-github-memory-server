# Fix for write_note Title Parameter Issue

## Problem
The `write_note` MCP tool was rejecting the `title` parameter with the error:
```
Error calling tool: Parameter 'title' must be of type string,null, got string
```

## Root Cause
The issue was caused by two problems:

1. **Missing `#[serde(default)]` attributes**: The `SaveParams` struct had several `Option<T>` fields (`title`, `r#type`, `ttl`, `score`) that were missing the `#[serde(default)]` attribute, causing inconsistent serialization/deserialization behavior.

2. **JSON Schema compatibility issue**: The generated JSON Schema used `"type": ["string", "null"]` for optional fields, which Cursor's MCP client validator was misinterpreting. It was treating `["string", "null"]` as a single type name "string,null" instead of a union of types.

## Fix Applied

### 1. Added `#[serde(default)]` to SaveParams (crates/proto/src/methods.rs)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SaveParams {
    #[serde(default)]           // Added
    pub title: Option<String>,
    pub content: String,
    #[serde(rename = "type", default)]  // Added default
    pub r#type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]           // Added
    pub ttl: Option<String>,
    #[serde(default)]           // Added
    pub score: Option<f32>,
    #[serde(default)]
    pub project: Option<String>,
}
```

### 2. Schema Post-Processing (crates/server/src/lib.rs)
Added a `fix_nullable_types()` function that transforms JSON Schema types from `["string", "null"]` to just `"string"` (keeping the `"default": null` to indicate optionality). This makes the schema more compatible with various JSON Schema validators.

```rust
fn fix_nullable_types(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(type_value) = map.get_mut("type") {
                if let Some(type_array) = type_value.as_array() {
                    if type_array.len() == 2 {
                        let has_null = type_array.iter().any(|v| v.as_str() == Some("null"));
                        let other_type = type_array.iter().find(|v| v.as_str() != Some("null"));
                        
                        if has_null && other_type.is_some() {
                            *type_value = other_type.unwrap().clone();
                        }
                    }
                }
            }
            
            for (_, v) in map.iter_mut() {
                fix_nullable_types(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                fix_nullable_types(item);
            }
        }
        _ => {}
    }
}
```

## Testing the Fix

To activate the fix, you need to restart the MCP server:

1. **Restart Cursor** (easiest method):
   - Quit Cursor completely
   - Reopen Cursor
   - The MCP server will automatically use the new binary

2. **Or kill the MCP server process**:
   ```bash
   pkill -f "gitmem serve"
   ```
   - Then restart Cursor or wait for it to auto-restart the server

3. **Verify the fix**:
   Try creating a note with a title:
   ```
   Use write_note to save: Title "Test", Content "Testing the fix"
   ```

## Files Modified
- `crates/proto/src/methods.rs` - Added `#[serde(default)]` attributes
- `crates/server/src/lib.rs` - Added schema post-processing function

## Build Status
✅ Release build successful: `./target/release/gitmem`

