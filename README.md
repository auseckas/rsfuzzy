# Basic usage

```
#[macro_use]
extern crate rsfuzzy;
use std::collections::HashMap;

pub fn main() {
    let mut f_engine = rsfuzzy::Engine::new();

    let i_var1 = fz_input_var![
        ("down", "normal", vec![0.0, 30.0]),
        ("triangle", "low", vec![15.0, 30.0, 40.0]),
        ("triangle", "medium", vec![30.0, 40.0, 55.0]),
        ("triangle", "high", vec![40.0, 60.0, 75.0]),
        ("up", "critical", vec![60.0, 100.0])
    ];
    f_engine.add_input_var("var1", i_var1, 0, 100);

    let i_var2 = fz_input_var![
        ("down", "normal", vec![0.0, 30.0]),
        ("triangle", "low", vec![15.0, 30.0, 40.0]),
        ("triangle", "medium", vec![30.0, 40.0, 55.0]),
        ("triangle", "high", vec![40.0, 60.0, 75.0]),
        ("up", "critical", vec![60.0, 100.0])
    ];

    f_engine.add_input_var("var2", i_var2, 0, 100);

    let o_var = fz_output_var![
        ("down", "normal", vec![0.0, 30.0]),
        ("triangle", "low", vec![15.0, 30.0, 40.0]),
        ("triangle", "medium", vec![30.0, 40.0, 55.0]),
        ("triangle", "high", vec![40.0, 60.0, 75.0]),
        ("up", "critical", vec![60.0, 100.0])
    ];
    f_engine.add_output_var("output", o_var, 0, 100);

    let f_rules = vec![
        ("if var1 is normal and var2 is normal then output is normal"),
        ("if var1 is very low and var2 is normal then output is very low"),
        ("if var1 is low then output is low"),
        ("if var1 is medium then output is medium"),
        ("if var1 is high then output is high"),
        ("if var1 is critical then output is critical"),
        ("if var1 is low and var2 is high then output is medium"),
    ];

    f_engine.add_rules(f_rules);
    f_engine.add_defuzz("centroid");

    let inputs = fz_set_inputs![
        ("var1", 21.2),
        ("var2", 61.5)
    ];

    let result = f_engine.calculate(inputs);
}

```
