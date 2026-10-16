//! DTrait v0 特征序列化。输入为真实采集器已归一化的值；不制造设备特征。
use std::collections::BTreeMap;
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Default)]
pub struct FeatureProtocol {
    booleans: BTreeMap<u8,bool>,
    central: BTreeMap<u8,u32>,
    edge: BTreeMap<u8,u32>,
}
impl FeatureProtocol {
    pub fn new() -> Self { Self::default() }
    /// 字段名与官方 v0 表一致；未定义的字段忽略。
    pub fn add_bool(&mut self, name: &str, value: bool) {
        if let Some(id)=field_id(name) { self.booleans.insert(id,value); }
    }
    /// 正常采集器把原始值转成32位哈希后写入；边缘再次哈希十进制表示。
    pub fn add_hash(&mut self, name: &str, value: u32) {
        if let Some(id)=field_id(name).filter(|id|*id>=32) {
            self.central.insert(id,value);
            self.edge.insert(id,murmur3(&value.to_string()));
        }
    }
    pub fn result(&self) -> (String,String) {
        encode(0,1,0,&self.booleans,&BTreeMap::new(),&self.central,&self.edge)
    }
}
fn field_id(name:&str)->Option<u8> {
    if let Some(n)=name.strip_prefix("bool_").and_then(|x|x.parse::<u8>().ok()).filter(|n|(1..=10).contains(n)) {
        return (name==format!("bool_{n}")).then_some(n);
    }
    let n=name.strip_prefix("str_")?.parse::<u8>().ok()?;
    if name!=format!("str_{n}") {return None;}
    match n {1..=33=>Some(n+31),34=>Some(71),_=>None}
}
/// MurmurHash3 x86_32，UTF-8输入，seed=0，无Unicode正规化。
pub fn murmur3(text:&str)->u32 {
    let bytes=text.as_bytes();let mut h=0u32;
    for chunk in bytes.chunks_exact(4) {
        let mut k=u32::from_le_bytes(chunk.try_into().unwrap());
        k=k.wrapping_mul(0xcc9e2d51).rotate_left(15).wrapping_mul(0x1b873593);
        h^=k;h=h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let tail=bytes.chunks_exact(4).remainder();let mut k=0u32;
    for (i,b) in tail.iter().enumerate(){k|=(*b as u32)<<(i*8);}
    if !tail.is_empty(){h^=k.wrapping_mul(0xcc9e2d51).rotate_left(15).wrapping_mul(0x1b873593);}
    h^=bytes.len() as u32;h^=h>>16;h=h.wrapping_mul(0x85ebca6b);h^=h>>13;h=h.wrapping_mul(0xc2b2ae35);h^(h>>16)
}
fn records(values:&BTreeMap<u8,u32>)->Vec<u8>{
    let mut out=Vec::with_capacity(values.len()*5);
    for (id,value) in values {out.push(*id);out.extend_from_slice(&value.to_be_bytes());}out
}
fn encode(reserved:u8,kind:u8,version:u8,booleans:&BTreeMap<u8,bool>,numbers:&BTreeMap<u8,u32>,central:&BTreeMap<u8,u32>,edge:&BTreeMap<u8,u32>)->(String,String){
    let max=booleans.keys().copied().max().unwrap_or(0) as usize;
    let mut bits=vec![0u8;(max/32+1)*5];
    for (id,value) in booleans {
        let id=*id as usize;
        // 保留官方块编号的非标准偏移；官方向量覆盖32/64边界。
        if id%32==0 {bits[id/32]=(id/8) as u8;}
        if *value {bits[5*(id/32+1)-(id%32/8)-1]|=1u8<<(id%8);}
    }
    let mut prefix=vec![(reserved<<6)|(kind<<5)|version];prefix.extend(bits);prefix.extend(records(numbers));
    let build=|strings| {let mut out=prefix.clone();out.extend(records(strings));STANDARD.encode(out)};
    // 官方edge也复用central头，不额外设置access-type位。
    (build(central),build(edge))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn vectors()->serde_json::Value{serde_json::from_str(include_str!("sdk/pcim_features_baseline.json")).unwrap()}
    #[test]
    fn all_official_serialization_states_match() {
        for case in vectors().as_array().unwrap(){
            let s=&case["state"];
            let nums=|key|s[key].as_object().unwrap().iter().map(|(k,v)|(k.parse::<u8>().unwrap(),v.as_u64().unwrap() as u32)).collect::<BTreeMap<_,_>>();
            let b=s["boolFeatures"].as_object().unwrap().iter().map(|(k,v)|(k.parse::<u8>().unwrap(),v.as_bool().unwrap())).collect();
            let (central,edge)=encode(s["reserved"].as_u64().unwrap() as u8,s["dTraitType"].as_u64().unwrap() as u8,s["version"].as_u64().unwrap() as u8,&b,&nums("numberFeatures"),&nums("centralStringFeatures"),&nums("edgeStringFeatures"));
            assert_eq!(central,case["result"]["centralString"],"{}",case["name"]);
            assert_eq!(edge,case["result"]["edgeString"],"{}",case["name"]);
        }
    }
    #[test]
    fn normalized_hash_inputs_match_official_methods() {
        let mut p=FeatureProtocol::new();assert_eq!(p.result(),("IAAAAAAA".into(),"IAAAAAAA".into()));
        p.add_hash("str_1",305419896);
        assert_eq!(p.result(),("IAAAAAAAIBI0Vng=".into(),"IAAAAAAAII7VA8w=".into()));
        let before=p.result();p.add_hash("str_01",1);p.add_hash("unknown",1);assert_eq!(p.result(),before);
        let mut p=FeatureProtocol::new();p.add_hash("str_34",u32::MAX);p.add_bool("bool_10",true);p.add_hash("str_2",7);p.add_bool("bool_1",true);p.add_hash("str_1",1);p.add_hash("str_2",9);p.add_bool("bool_2",false);
        assert_eq!(p.result(),("IAAAAAQCIAAAAAEhAAAACUf/////".into(),"IAAAAAQCIJQWrJMhJIvmoUfG4asX".into()));
    }
    #[test]
    fn unicode_murmur_matches_original_vm() {
        assert_eq!(murmur3("公开合成\0\n😀"),4161292799);
        assert_eq!(murmur3("e\u{301}é"),215891940);
        assert_ne!(murmur3("e\u{301}"),murmur3("é"));
    }
}
