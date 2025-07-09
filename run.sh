#!/bin/bash

cd server && python server.py &
pwd &
cd .. &
cd networks && python network2.py