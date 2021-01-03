# -*- coding: utf-8 -*-
import scrapy
from math import ceil
import re
from cve_details.items import CveDetailsItem

class CveDetailSpider(scrapy.Spider):
    name = 'cve_detail'
    allowed_domains = ['https://www.cvedetails.com']
    goturls = set()

    def start_requests(self):
        for i in range(2020, 1998, -1):
            url = "https://www.cvedetails.com/vulnerability-list/year-" + str(i) + "/vulnerabilities.html"
            yield scrapy.Request(url=url, meta={'year' : i})

    def get_url(self, page, year, trc, sha):
        return "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page={}&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year={}&month=0&cweid=0&order=1&trc={}&sha={}".format(page, year, trc, sha)

    def parse(self, response):
        # 得到页数，生成url
        nums = response.selector.xpath('//div[@id="pagingb"]/b/text()').get()                   # 获取cve的数量
        pages = ceil(int(nums)/50)                                                              # 算出页数
        sha = response.selector.xpath('//a[@title="Go to page 1"]/@href').get()  
        if sha != None:
            sha = sha.split('=')[-1]                                                            # 获取sha
        else:
            return None
        for page in range(1, pages+1):
            newurl = self.get_url(str(page), str(response.meta['year']), str(nums), sha)
            if newurl not in self.goturls:
                self.goturls.add(newurl)
                yield scrapy.Request(url=newurl, callback=self.parse1, dont_filter=True)
            else:
                print('p0访问重复！！！')
                break
    
    def parse1(self, response):
        detailurls = response.selector.xpath('//div[@id="searchresults"]/table/tr[@class="srrowns"]/td[@nowrap]/a/@href').getall()
        for detailurl in detailurls:
            durl = "https://www.cvedetails.com" + detailurl
            if durl not in self.goturls:
                self.goturls.add(durl)
                yield scrapy.Request(url=durl, callback=self.parse2, dont_filter=True)
            else:
                print('p1访问重复！！！')
                break

    def parse2(self, response):
        # CVE编号，危害等级，漏洞类型，供应商，型号，设备类型，固件版本号
        cveid = response.selector.xpath('//h1/a/text()').get()
        score = response.selector.xpath('//div[@class="cvssbox"]/text()').get()
        vulntype =  re.findall(r'">(.*?)</span>', response.selector.xpath('//table[@id="cvssscorestable"]/tr').getall()[-2])
        vulntype = '' if vulntype == [] else vulntype[0]
        makes = response.selector.xpath('//table[@id="vulnprodstable"]/tr').getall()[1:]   
        rule1 = re.compile(r'<a .*>(.*)</a>')
        rule2 = re.compile(r'<td>\s+(.*?)\s+</td>')
        for make in makes:
            if 'No vulnerable product found' in make:
                continue
            vendor,product,_ = rule1.findall(make)
            producttype,_,_,version,_,_,_,_ = rule2.findall(make)
            item = CveDetailsItem()
            item['cveid'],item['score'],item['vulntype'],item['vendor'],item['product'],item['producttype'],item['version'] = cveid,score,vulntype,vendor,product,producttype,version
            yield item
