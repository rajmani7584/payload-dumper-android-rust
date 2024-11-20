use payload::Payload;


mod payload;
mod chromeos_update_engine;


fn main() {
    let filename = "ota/payload.bin";

    // let res = payload.get_partition_list();

    let mut payload = Payload::new(filename.to_string());

    let mut payload = payload.as_mut().unwrap();

    let res = payload.extract("boot", "out/boot.img", &|progress| println!("{}%", progress));

    match res {
        Ok(res) => println!("{}", res),
        Err(err) => println!("{}", err)
    }
}
