# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
# from itemadapter import ItemAdapter
import pymysql

class CveDetailsPipeline:
    tb = 'cve_details'
    number = 0

    def open_spider(self, spider):
        print("开始爬虫！")
        db = spider.settings.get('MYSQL_DB_NAME','cve_db')
        host = spider.settings.get('MYSQL_HOST','127.0.0.1')
        port = spider.settings.get('MYSQL_PORT', 3306)
        user = spider.settings.get('MYSQL_USER','root')
        passwd = spider.settings.get('MYSQL_PASSWORD','root')

        self.db_conn =pymysql.connect(host=host, port=port, db=db, user=user, passwd=passwd, charset='utf8')
        self.db_cur = self.db_conn.cursor()

        self.db_cur.execute("DROP TABLE IF EXISTS %s"%self.tb)
        sql = """CREATE TABLE IF NOT EXISTS %s (
            id int PRIMARY KEY AUTO_INCREMENT, 
            cveid varchar(32) NOT NULL,
            score varchar(16),
            vulntype varchar(100),
            vendor varchar(56),
            product varchar(56),
            producttype varchar(32),
            version varchar(32)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
        """
        self.db_cur.execute(sql%self.tb)
        print('建表完成！')
        

    def process_item(self, item, spider):
        if item != None:
            values = (
                pymysql.escape_string(item['cveid']),           # CVE编号
                pymysql.escape_string(item['score']),           # 危害等级
                pymysql.escape_string(item['vulntype']),        # 漏洞类型
                pymysql.escape_string(item['vendor']),          # 供应商
                pymysql.escape_string(item['product']),         # 型号
                pymysql.escape_string(item['producttype']),     # 设备类型
                pymysql.escape_string(item['version'])          # 固件版本号
            )
            # print(type(item['cveid']),type(item['score']),type(item['vulntype']),type(item['vendor']),type(item['product']),type(item['producttype']),type(item['version']))

            sql = '''INSERT INTO cve_details(cveid,score,vulntype,vendor,product,producttype,version) VALUES(%s,%s,%s,%s,%s,%s,%s)'''
            self.db_cur.execute(sql, values)
            self.number += 1
            if self.number >= 200:
                self.db_conn.commit()
                self.number = 0
        return item

    def close_spider(self, spider):
        print("结束爬虫！")
        self.db_conn.commit()
        self.db_conn.close()