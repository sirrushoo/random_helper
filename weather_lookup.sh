#!/bin/bash

echo "Enter city if it's multiple words use a + (plus) to combine them"
echo "You can use three letter airport code or land marks such as Eiffel+Tower"

read city

curl wttr.in/$city
