// Copyright 2015 Threat X, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

#[derive(Debug, Clone)]
pub enum MfType {
    Triangle(Triangle),
    Trapezoid(Trapezoid),
    Up(Up),
    Down(Down)
}

impl MfType {
    pub fn compute(&self, x: f32) -> f32 {
        match *self {
            MfType::Triangle(ref value) => value.compute(x),
            MfType::Trapezoid(ref value) => value.compute(x),
            MfType::Up(ref value) => value.compute(x),
            MfType::Down(ref value) => value.compute(x)
        }
    }
    
    pub fn name(&self) -> &str {
        match *self {
            MfType::Triangle(ref value) => value.name(),
            MfType::Trapezoid(ref value) => value.name(),
            MfType::Up(ref value) => value.name(),
            MfType::Down(ref value) => value.name()
        }
    }

    
}

#[derive(Debug, Clone)]
pub struct Triangle {
    name: String,
    a: f32,
    b: f32,
    c: f32
}

impl Triangle {
    pub fn new(name: &str, init: Vec<f32>) -> MfType {
        if init.len() != 3 {
            panic!("init var for Triangle needs 3 values");
        }
        let triangle = Triangle {
            name: name.to_owned(),
            a: init[0],
            b: init[1],
            c: init[2]
        };
        MfType::Triangle(triangle)
    }
    
    fn compute(&self, x: f32) -> f32 {
        let g1 = (x - self.a) / (self.b - self.a);
        let g2 = (self.c - x) / (self.c - self.a);
        0f32.max(g1.min(g2))
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct Trapezoid {
    name: String,
    a: f32,
    b: f32,
    c: f32,
    d: f32
}

impl Trapezoid {
    pub fn new(name: &str, init: Vec<f32>) -> MfType {
        if init.len() != 4 {
            panic!("init var for Trapezoid needs 3 values");
        }
        let trapezoid = Trapezoid {
            name: name.to_owned(),
            a: init[0],
            b: init[1],
            c: init[2],
            d: init[3]
        };
        MfType::Trapezoid(trapezoid)
    }
    
    fn compute(&self, x: f32) -> f32 {
        let g1 = (x - self.a) / (self.b - self.a);
        let g2 = (self.d - x) / (self.d - self.c);
        g1.min(g2).min(1f32).max(0f32)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct Up {
    name: String,
    a: f32,
    b: f32
}

impl Up {
    pub fn new(name: &str, init: Vec<f32>) -> MfType {
        if init.len() != 2 {
            panic!("init var for Up needs 2 values");
        }
        let up = Up {
            name: name.to_owned(),
            a: init[0],
            b: init[1]
        };
        MfType::Up(up)
    }

    fn compute(&self, x: f32) -> f32 {
        if x < self.a {
            return 0f32
        }
        if x > self.b {
            return 1f32
        }
       (x - self.a) / (self.b - self.a)
        
    }

    fn name(&self) -> &str {
        &self.name
    }
    
}

#[derive(Debug, Clone)]
pub struct Down {
    name: String,
    a: f32,
    b: f32
}

impl Down {
    pub fn new(name: &str, init: Vec<f32>) -> MfType {
        if init.len() != 2 {
            panic!("init var for Up needs 2 values");
        }
        let down = Down {
            name: name.to_owned(),
            a: init[0],
            b: init[1]
        };
        MfType::Down(down)
    }

    fn compute(&self, x: f32) -> f32 {
        let up = Up::new(&self.name, vec![self.a, self.b]);
        1f32 - up.compute(x)
        
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}
