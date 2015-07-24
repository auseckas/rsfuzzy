// Copyright 2015 Threat X, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

use std::vec::Vec;
use std::collections::HashMap;
use std::fmt;

pub mod mf;
pub mod deffuz;
pub mod hedges;

static OPERATOR: [&'static str; 3] = ["and", "or", "not"];

use hedges::Hedge;
use deffuz::{DefuzzType, Centroid, Mom, DefuzzOp};
use std::f32;

pub struct Engine {
    inputs: HashMap<String, InputVar>,
    output: HashMap<String, OutputVar>,
    rules: Vec<(Vec<(mf::MfType, Option<Box<Hedge>>, Option<DefuzzOp>)>, Option<Box<Hedge>>, mf::MfType)>,
    range: (usize, usize),
    defuzz: DefuzzType,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Inputs: {:?}\nOutputs: {:?}\nRules: {:?}", self.inputs, self.output, self.rules)
    }
}


impl Engine {
    pub fn new() -> Engine {
        Engine {
            inputs: HashMap::with_capacity(3),
            output: HashMap::with_capacity(1),
            rules: Vec::new(),
            range: (0, 0),
            defuzz: DefuzzType::Undefined,
        }
    }
    
    pub fn add_input_var(&mut self, name: &str, input_var: InputVar, start: usize, end: usize) {
        let mut i_var = input_var;
        i_var.start(start);
        i_var.end(end);
        self.inputs.insert(name.to_owned(), i_var);
    }

    pub fn add_output_var(&mut self, name: &str, output_var: OutputVar, start: usize, end: usize) {
        let mut o_var = output_var;
        o_var.start(start);
        o_var.end(end);
        self.output.insert(name.to_owned(), o_var);
    }
    
    pub fn add_defuzz(&mut self, name: &str) {
        let defuzz = match name {
            "centroid" => DefuzzType::Centroid(Centroid),
            "mom" => DefuzzType::Mom(Mom),
            _ => DefuzzType::Undefined
        };
        if let DefuzzType::Undefined = defuzz {
            panic!("Defuzzification type '{}' is not defined", name);
        }
        self.defuzz = defuzz;
    }
    
    pub fn add_rules(&mut self, rules: Vec<&str>) {
        let hedges = hedges::types();
        let operators: Vec<&'static str> = OPERATOR.iter().map(|&x| x).collect();
        let mut idx;
        let mut input_hedge: Option<Box<Hedge>>;
        let mut output_hedge: Option<Box<Hedge>>;
        let mut operator: Option<DefuzzOp>;
        for rule in rules {
            let fields: Vec<&str> = rule.trim().split(' ').collect();
            idx = 0;
            input_hedge = None;
            output_hedge = None;
            let mut input_vars: Vec<(mf::MfType, Option<Box<Hedge>>, Option<DefuzzOp>)> = Vec::new();
            if fields[idx] != "if" {
                panic!("Invalid syntax. 'if' missing in '{}'", rule);
            }
            idx += 1;
            
            loop {
                let src_field;
                if let Some(value) = self.inputs.get(fields[idx]) {
                    src_field = value;
                }
                else {
                    panic!("Input field: '{}' not found", fields[idx]);
                }
                idx += 1;
                if fields[idx] != "is" {
                    panic!("Invalid syntax. 'is' missing in '{}'", rule);
                }
                idx += 1;
            
                loop {
                    if hedges.contains(&fields[idx]) {
                        input_hedge = Some(Box::new(Hedge::new(fields[idx], input_hedge))); 
                        idx += 1;
                    } else {
                        break;
                    }
                }
                let input_var;
                if let Some(value) = src_field.get(fields[idx]) {
                    input_var = value;
                }
                else {
                    panic!("Invalid syntax. Input var '{}' not found", fields[idx]);
                }
                idx += 1;
                if operators.contains(&fields[idx]) {
                    operator = match fields[idx]{
                        "and" => Some(DefuzzOp::And),
                        "or" => Some(DefuzzOp::Or),
                        "not" => Some(DefuzzOp::Not),
                        _ => panic!("Operator '{}' not found!", fields[idx])
                    };
                    input_vars.push((input_var.clone(), input_hedge.clone(), operator));
                    idx += 1;
                }
                else {
                    input_vars.push((input_var.clone(), input_hedge.clone(), None));
                    break;
                }
                
            }

            if fields[idx] != "then" {
                panic!("Invalid syntax. 'then' missing in '{}'", rule);
            }
            idx += 1;
            
            let dst_field;
            if let Some(value) = self.output.get(fields[idx]) {
                dst_field = value;
            }
            else {
                panic!("Output field: '{}' not found", fields[idx]);
            }
            idx += 1;
            if fields[idx] != "is" {
                panic!("Invalid syntax. 'is' missing in '{}'", rule);
            }
            idx += 1;
            loop {
                if hedges.contains(&fields[idx]) {
                    output_hedge = Some(Box::new(Hedge::new(fields[idx], output_hedge))); 
                    idx += 1;
                } else {
                    break;
                }
            }
            let output_var;
            if let Some(value) = dst_field.get(fields[idx]) {
                output_var = value;
            }
            else {
                panic!("Invalid syntax. Output var '{}' not found", fields[idx]);
            }
            self.range = dst_field.range();
            self.rules.push((input_vars.clone(), output_hedge.clone(), output_var.clone()));
        }
    }
    
    pub fn calculate(&self, x: f32) -> f32 {
        let (start, end) = self.range;
        if let DefuzzType::Undefined =  self.defuzz {
            return f32::NAN;
        }
        self.defuzz.get(start, end, &self.rules, x)
    }
    
}

#[derive(Debug, Clone)]
pub struct InputVar {
    vars: Vec<mf::MfType>,
    start: usize,
    end: usize
}

impl InputVar {
    pub fn new(input: Vec<mf::MfType>) -> InputVar{
        InputVar {
            vars: input,
            start: 0,
            end: 0
        }
    }
    
    fn start(&mut self, start: usize) {
        self.start = start;
    }

    fn end(&mut self, end: usize) {
        self.end = end;
    }
    
    fn get(&self, name: &str) -> Option<&mf::MfType>{
        for var in &self.vars {
            if var.name() == name {
                return Some(var);
            }
        }
        None
    }

}

#[derive(Debug, Clone)]
pub struct OutputVar {
    vars: Vec<mf::MfType>,
    start: usize,
    end: usize
}

impl OutputVar {
    pub fn new(input: Vec<mf::MfType>) -> OutputVar{
        OutputVar {
            vars: input,
            start: 0,
            end: 0
        }
    }
    
    fn start(&mut self, start: usize) {
        self.start = start;
    }

    fn end(&mut self, end: usize) {
        self.end = end;
    }

    fn get(&self, name: &str) -> Option<&mf::MfType>{
        for var in &self.vars {
            if var.name() == name {
                return Some(var);
            }
        }
        None
    }

    fn range(&self) -> (usize, usize) {
        (self.start, self.end)
    }
}


#[macro_export]
macro_rules! fz_input_var {
    ( $( $x:expr ),* ) => {
        {
            let mut vars: Vec<fuzzy::mf::MfType> = Vec::new();
            $(
                let value = match $x.0 {
                    "triangle" => fuzzy::mf::Triangle::new($x.1, $x.2),
                    "trapezoid" => fuzzy::mf::Trapezoid::new($x.1, $x.2),
                    "up" => fuzzy::mf::Up::new($x.1, $x.2),
                    "down" => fuzzy::mf::Down::new($x.1, $x.2),
                    _ => return Err(TXParserError::from_complex("No MF found for type", $x.0))
                    
                };
               vars.push(value);
                
            )*
            fuzzy::InputVar::new(vars)
        }
    };
}

#[macro_export]
macro_rules! fz_output_var {
    ( $( $x:expr ),* ) => {
        {
            let mut vars: Vec<fuzzy::mf::MfType> = Vec::new();
            $(
                let value = match $x.0 {
                    "triangle" => fuzzy::mf::Triangle::new($x.1, $x.2),
                    "trapezoid" => fuzzy::mf::Trapezoid::new($x.1, $x.2),
                    "up" => fuzzy::mf::Up::new($x.1, $x.2),
                    "down" => fuzzy::mf::Down::new($x.1, $x.2),
                    _ => return Err(TXParserError::from_complex("No MF found for type", $x.0))
                    
                };
               vars.push(value);
                
            )*
            fuzzy::OutputVar::new(vars)
        }
    };
}
