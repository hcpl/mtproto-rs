use log::info;
//use mtproto::tl::TLConstructorsMap;
use mtproto::schema::{constructors, types};
//use serde::de::DeserializeSeed;
use serde_mtproto::Boxed;


fn main() {
    env_logger::init();
    dotenv::dotenv().ok();

    //let mut cmap = TLConstructorsMap::new();
    //types::register_ctors(&mut cmap);
    //info!("{:#?}", &cmap);

    let answer = types::Set_client_DH_params_answer::dh_gen_retry(constructors::dh_gen_retry {
        nonce: "100".parse().unwrap(),
        server_nonce: "20000".parse().unwrap(),
        new_nonce_hash2: "821349182".parse().unwrap(),
    });
    let x = Boxed::new(answer);
    info!("{:#?}", &x);

    let s = serde_mtproto::to_bytes(&x).unwrap();
    info!("{:?}", &s);

    let x2: Boxed<types::Set_client_DH_params_answer> = serde_mtproto::from_bytes(&s, &["dh_gen_retry"]).unwrap();
    info!("{:#?}", &x2);

    assert_eq!(&x, &x2);

    //let x3 = cmap.deserialize(&mut serde_mtproto::Deserializer::new(&*s, &["dh_gen_retry"])).unwrap();
    //info!("{:#?}", &x3);

    //let x4 = Boxed::new(x3);
    //info!("{:#?}", &x4);

    //let s2 = serde_mtproto::to_bytes(&x4).unwrap();
    //info!("{:?}", &s2);

    //let x5: Boxed<types::Set_client_DH_params_answer> = serde_mtproto::from_bytes(&s2, &["dh_gen_retry"]).unwrap();
    //info!("{:#?}", &x5);

    //assert_eq!(&x, &x5);
}
