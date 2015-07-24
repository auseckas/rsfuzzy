// Copyright 2015 Threat X, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0


static TYPES: [&'static str; 4] = ["very", "extremely", "somewhat", "slightly"];

pub fn types() -> Vec<&'static str> {
    TYPES.iter().map(|&x| x).collect()
}

pub fn compute(hedge: &Hedge, x: f32) -> f32 {
    hedge.compute(x)
}

#[derive(Debug, Clone)]
pub struct Hedge {
    hedge: Option<Box<Hedge>>,
    p: f32
}

impl Hedge {
    pub fn new(name: &str, hedge: Option<Box<Hedge>>) -> Hedge {
        match name {
            "very" => Hedge::init_very(hedge),
            "extremely" => Hedge::init_extremely(hedge),
            "somewhat" => Hedge::init_somewhat(hedge),
            "slightly" => Hedge::init_slightly(hedge),
            _ => panic!("Hedge: '{}' does not exists!", name)
        }
    }

    fn init(hedge: Option<Box<Hedge>>, p: f32) -> Hedge {
        Hedge {
            hedge: hedge,
            p: p
        }
    }
   
    fn init_very(hedge: Option<Box<Hedge>>) -> Hedge {
        Hedge::init(hedge, 2f32)
    }

    pub fn init_extremely(hedge: Option<Box<Hedge>>) -> Hedge {
        Hedge::init(hedge, 3f32)
    }

    pub fn init_somewhat(hedge: Option<Box<Hedge>>) -> Hedge {
        Hedge::init(hedge, 0.5f32)
    }

    pub fn init_slightly(hedge: Option<Box<Hedge>>) -> Hedge {
        Hedge::init(hedge, 1f32 / 3f32)
    }
    
    pub fn compute(&self, x: f32) -> f32 {
        let mut y = x;
        if let Some(ref hedge) = self.hedge {
            if x > 0.0 {
                y = hedge.compute(x);
            }
        }
        y.powf(self.p)
    }
    
}
