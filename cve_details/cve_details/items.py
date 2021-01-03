# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CveDetailsItem(scrapy.Item):
    # define the fields for your item here like:
    cveid = scrapy.Field()
    score = scrapy.Field()
    vulntype = scrapy.Field()
    vendor = scrapy.Field()
    product = scrapy.Field()
    producttype = scrapy.Field()
    version = scrapy.Field()
    
