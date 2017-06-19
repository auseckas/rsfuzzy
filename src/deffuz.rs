// Copyright 2015 Threat X, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

use std::collections::HashMap;
use hedges::Hedge;
use mf;

#[derive(Debug, Clone)]
pub enum DefuzzType {
    Centroid(Centroid),
    Mom(Mom),
    Undefined
}

#[derive(Debug, Clone)]
pub enum DefuzzOp {
    And,
    Or,
    Not
}


impl DefuzzType {
    pub fn get(&self, start: usize, end: usize, rules: &Vec<(Vec<(String, mf::MfType, Option<Box<Hedge>>, Option<DefuzzOp>)>, Option<Box<Hedge>>, mf::MfType)>, inputs: HashMap<String, f32>) -> f32 {
        match *self {
            DefuzzType::Centroid(ref value) => value.get(start, end, rules, inputs),
            DefuzzType::Mom(ref value) => value.get(start, end, rules, inputs),
            DefuzzType::Undefined => panic!("Cannot use 'Undefined' to defuzzify!")
        }
    }
}

#[derive(Debug, Clone)]
pub struct Centroid;

impl Centroid {
    pub fn get(&self, start: usize, end: usize, rules: &Vec<(Vec<(String, mf::MfType, Option<Box<Hedge>>, Option<DefuzzOp>)>, Option<Box<Hedge>>, mf::MfType)>, inputs: HashMap<String, f32>) -> f32 {
        println!("Start: {:?}, end: {:?}", start, end);
        let fdom: Vec<f32> = (start..end).map(|y| {
            let mut values: Vec<f32> = Vec::with_capacity(rules.len());
            for rule in rules {
                let input_vars = &rule.0;
                let output_hedge = &rule.1;
                let output_obj = &rule.2;
                let mut val;
                let mut prev_val = 0f32;
                let mut oper = &None;
                let mut output = 0f32;
                for var in input_vars {
                    let input_name = &var.0;
                    let input_obj = &var.1;
                    println!("Input: {:?}", input_name);
                    let input_hedge = &var.2;
                    let operator = &var.3;
                    let x = match inputs.get(input_name) {
                        Some(val) => val,
                        None => panic!("Variable {} not defined.", input_name)
                    };
                    val = input_obj.compute(*x);
                    if let Some(ref hedge) = *input_hedge {
                        val = hedge.compute(val);
                    }
                    output = output_obj.compute(y as f32) * val;
                    if let Some(ref hedge) = *output_hedge {
                        output = hedge.compute(output);
                    }
                    if let Some(ref op) = *oper {
                        output = match *op {
                            DefuzzOp::And => prev_val.min(output),
                            DefuzzOp::Or => prev_val.max(output),
                            DefuzzOp::Not => 1f32 - prev_val
                        }
                    }
                    oper = operator;
                    prev_val = output;
                }
                values.push(output);
            }
            values.iter().fold(0f32, |a, b| a + b)
        }).collect();
        println!("Fdom: {:?}", fdom);
        let z_pairs = (start..end).zip(fdom.iter());
        let map_first = z_pairs.map(|(a, b)| a as f32 * b);
        let first = map_first.fold(0f32, |a, b| a + b);
        let second = fdom.iter().fold(0f32, |a, b| a + b);
        first / second
    }
}

#[derive(Debug, Clone)]
pub struct Mom;

impl Mom {
    pub fn get(&self, start: usize, end: usize, rules: &Vec<(Vec<(String, mf::MfType, Option<Box<Hedge>>, Option<DefuzzOp>)>, Option<Box<Hedge>>, mf::MfType)>, inputs: HashMap<String, f32>) -> f32 {
        let mut result: Vec<f32> = Vec::with_capacity(rules.len() + 5);
        let range: Vec<f32> = (start..end).map(|x| x as f32).collect();
        let mut values: Vec<(f32, f32)> = Vec::with_capacity(end as usize + 1);
        let mut xmax: f32;
        let mut val;
        let mut prev_val;
        let mut x;
        let mut input_obj;
        let mut input_name;
        let mut input_hedge;
        let mut operator;

        for rule in rules {
            xmax = 0f32;
            values.clear();
            let input_vars = &rule.0;
            let output_hedge = &rule.1;
            let output_obj = &rule.2;

            for &i in range.iter() {
                val = 0f32;
                prev_val = 0f32;
                let mut oper = &None;
                for var in input_vars {
                    input_name = &var.0;
                    input_obj = &var.1;
                    input_hedge = &var.2;
                    operator = &var.3;

                    let i_crisp = match inputs.get(input_name) {
                        Some(val) => val,
                        None => panic!("Variable {} not defined.", input_name)
                    };

                    val = input_obj.compute(*i_crisp);
                    if let Some(ref hedge) = *input_hedge {
                        val = hedge.compute(val);
                    }
                    if let Some(ref op) = *oper {
                        val = match *op {
                            DefuzzOp::And => prev_val.min(val),
                            DefuzzOp::Or => prev_val.max(val),
                            DefuzzOp::Not => 1f32 - prev_val
                        }
                    }
                    oper = operator;
                    prev_val = val;
                }
                x = output_obj.compute(i) * val;
                if let Some(ref hedge) = *output_hedge {
                    x = hedge.compute(x);
                }
                if x >= xmax {
                    xmax = x;
                }
                values.push((i, x));
            };

            let fdom: Vec<f32> = values.iter().filter_map(|&var| {
                let (i, x) = var;
                if x > 0.0 && x == xmax {
                    Some(i)
                }
                else {
                    None
                }
            }).collect();
            result.extend(fdom)
        }

        let sum_result = result.iter().fold(0f32, |a, &b| a + b);
        sum_result / result.len() as f32
    }
}
