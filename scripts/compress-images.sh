#!/bin/sh
magick mogrify -format webp -resize 70% -quality 80 -define webp:method=6 -alpha remove -define webp:lossless=false docs/images/*.png
