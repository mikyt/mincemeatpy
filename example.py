#!/usr/bin/env python
import mincemeat

data = ["Humpty Dumpty sat on a wall",
        "Humpty Dumpty had a great fall",
        "All the King's horses and all the King's men",
        "Couldn't put Humpty together again",
        ]

def mapfn(k, v):
    for w in v.split():
        yield w, 1

def reducefn(k, vs):
    result = sum(vs)
    return result

s = mincemeat.Server(password="changeme") 

# The data source can be any dictionary-like object 
s.mapfn = mapfn
s.reducefn = reducefn
s.start()

datasource = dict(enumerate(data)) 
results = s.process_datasource(datasource) 
print results

newdata = ["When the English tongue we speak",
           "Why is break not rhymed with weak?",
           "Won't you tell me why it's true",
           "We say sew, but also few?",
           "And the maker of a verse",
           "Cannot rhyme his horse with worse?",
           "Beard is not the same as heard,",
           "Cord is different from word,",
           "Cow is cow, low is low,",
           "Shoe is never rhymed with foe.",
           "Think of hose and dose and lose,",
           "And think of goose and yet of choose,",
           "Think of comb and tomb and bomb,",
           "Doll and roll and home and some.",
           "And since pay is rhymed with say,",
           "Why not paid with said I pray?",
           "Think of blood and food and good;",
           "Mould is not pronounced like could.",
           "Why is done, but gone and lone -",
           "Is there any reason known?",
           "To sum it up, it seems to me",
           "That sounds and letters don't agree."]
           
newdatasource = dict(enumerate(newdata))
newresults = s.process_datasource(newdatasource)
print newresults
