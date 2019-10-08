# encoding:utf-8
import requests
import re
from bs4 import BeautifulSoup
import csv
from copy import deepcopy


tags = ['Apache Hadoop', 'Apache Spark', 'Apache Hive', 'Apache Storm', 'Apache storm', 'Apache ranger', 'Apache kafka', 'Apache zookeeper', 'MySql', 'Redis']
# tags = ['mysql']
base_headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "Content-Length": "205",
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": "SESSION=19dd542c-7d1a-45fb-b167-20f6adae0146",
    "Host": "www.cnnvd.org.cn",
    "Origin": "http://www.cnnvd.org.cn",
    "Referer": "http://www.cnnvd.org.cn/web/vulnerability/queryLds.tag",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
}
base_data = {
    "CSRFToken": '',
    "cvHazardRating": '',
    "cvVultype": '',
    "qstartdateXq": '',
    "cvUsedStyle": '',
    "cvCnnvdUpdatedateXq": '',
    "cpvendor": '',
    "relLdKey": '',
    "hotLd": '',
    "isArea": '',
    "qcvCname": 'hadoop',
    "qcvCnnvdid": 'CNNVD或CVE编号',
    "qstartdate": '',
    "qenddate": '',
}

base_url = "http://www.cnnvd.org.cn/web/vulnerability/queryLds.tag"

ori_url = "http://www.cnnvd.org.cn"


# 存储数据
def store_data(file, cnnvd_ids, cve_ids, cnnvd_titles, cnnvd_urls, cnnvd_level, cnnvd_affver, cnnvd_patches, cnnvd_patches_links, update_time, tag):
    # print(cnnvd_ids)
    # print(cnnvd_titles)
    # print(cnnvd_urls)
    # print(cnnvd_level)
    # print(cnnvd_affver)
    # print(cnnvd_patches)
    with open(file, mode="w") as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'AFFECTED_VERSION', 'CNNVD_ID', 'CVE_ID', 'PATCHES', 'PATCHES_LINKS', 'TITLE', 'LEVEL','vun_type','URL', 'Update_Time'])
        for i in range(len(cnnvd_ids)):
            line = [str(i+1)]

            ver = ''
            for v in cnnvd_affver[i]:
                if v is not None:
                    ver = ver + v + ' '
            if ver == '':
                ver = 'null'
            patches = ''
            patches_links = ''
            for p in cnnvd_patches[i]:
                if p is not None:
                    patches = patches + p + ' '
            for l in cnnvd_patches_links[i]:
                if l is not None:
                    patches_links = patches_links + l + ' '

            line.append(ver.encode('utf-8'))
            line.append(cnnvd_ids[i].encode('utf-8'))
            line.append(cve_ids[i])
            line.append(patches.encode('utf-8'))
            line.append(patches_links.encode('utf-8'))
            line.append(cnnvd_titles[i].encode('utf-8'))
            line.append(cnnvd_level[i].encode('utf-8'))
            line.append(tag)
            line.append((ori_url + cnnvd_urls[i]).encode('utf-8'))
            line.append(update_time[i])
            writer.writerow(line)
            print(line)

        print(len(cnnvd_ids))
        f.close()


def cnnvd(tag):
    headers = deepcopy(base_headers)
    data = deepcopy(base_data)
    data["qcvCname"] = tag
    cnnvd_ids = []          # Vun ID
    cnnvd_titles = []          # Vun Name
    cnnvd_urls = []          # Vun Url
    cnnvd_level = []          # Vun Security Level
    cnnvd_affver = []          # Vun Affected Versions
    cnnvd_desc = []          # Vun Descriptions
    cnnvd_patches = []        # Vun Patches describes
    cnnvd_patches_links = []  # Vun patch links
    cve_ids = []              # Vun CVE IDs
    update_time = []          # Vun last update time

    r = requests.post(url=base_url, headers=headers, data=data, timeout=30)
    r.raise_for_status()
    text = r.text
    soup = BeautifulSoup(text, "html.parser")

    # page number
    pages = int(re.search(u'<input type="hidden" id="pagecount" name="pagecount" value="(\d+)"/>', text).group(1)) # body > div.container.m_t_10 > div > div.fl.w770 > div > div.page > a.page_a

    # total items of this vulnerability
    item_num = int(re.search(u'<a onmouse=\"\">总条数：(\d*?)</a>', text).group(1))

    # parser first page
    if (item_num > 10):
        curr_item = 10
        item_num = item_num - 10
    else:
        curr_item = item_num
    for i in range(curr_item):
        link = soup.select('#vulner_' + str(i) + ' > a')[0]
        cnnvd_ids.append(re.search(u'(CNNVD-[\d-]*?$)', link.get('href'), re.M | re.S).group(1))
        # cnnvd_titles.append(re.search(u'[\r\n\s\t]*(.*?$)', link.text, re.M | re.S).group(1))
        cnnvd_urls.append(link.get('href'))

    # parser the pages left
    for i in range(2, pages + 1):
        data['pageno'] = str(i)
        data['repairLd'] = ''
        if (item_num > 10):
            curr_item = 10
            item_num = item_num - 10
        else:
            curr_item = item_num
        r = requests.post(base_url, headers=headers, data=data)
        r.raise_for_status()
        text = r.text
        soup = BeautifulSoup(text, 'html.parser')
        for j in range(curr_item):
            link = soup.select('#vulner_' + str(j) + ' > a')[0]
            cnnvd_ids.append(re.search(u'(CNNVD-[\d-]*?$)', link.get('href'), re.M | re.S).group(1))
            # cnnvd_titles.append(re.search(u'[\r\n\s\t]*(.*?$)', link.text, re.M | re.S).group(1))  # 漏洞名称
            cnnvd_urls.append(link.get('href'))  # 漏洞url

    # get the level、affected versions and patches info
    for url in cnnvd_urls:
        r = requests.get(ori_url + url)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'lxml')

        aff_versions = []
        descs = []
        patches = []
        patches_links = []

        # titles
        cnnvd_titles.append(soup.select(u'body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > h2')[0].text)
        
        # cve_ids
        cve_temp = soup.select(u'body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(3) > a')[0].text
        cve = re.search(u'[\s](.*)[\r\n\s\t]*$', cve_temp).group(1)
        try:
            cve = re.search(u'(.*)[\r]$', cve).group(1)
        except:
            pass
        # print(cve)
        cve_ids.append(cve)

        # level
        try:
            level = re.search(
                u'<a style="color:#4095cc;cursor:pointer;" onclick="cnQueryByUrl\(\'vulnerability/querylist.tag\',\'cvHazardRating\',\'(.{2})\'\)">(.{2})',
                r.text).group(1)
        except:
            level = u""
        # print level

        # versions
        versions = re.findall(u'<a class="a_title2" style="cursor:auto; font-color:black">(.*)</a>', r.text)
        for v in versions:
            aff_versions.append(v)


        # describes
        describles = soup.select('body > div.container.m_t_10 > div > div.fl.w770 > div:nth-of-type(3)')[0].findAll('p')
        for d in describles:
            descs.append(re.search(u'[\r\n\s\t]*(.*)[\r\n\s\t]*$', d.text).group(1))
        
        # patches and the links
        lis = soup.select('#pat > li > div.fl > a')
        for li in lis:
            patches.append(li.string)
            # print(li.string)
            patches_links.append(ori_url + li.get('href'))
        
        time = soup.select('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(7) > a')[0].string
        time = re.search(u'([0-9]{4}-[0-9]{2}-[0-9]{2})', time).group(1)
        # print(time)

        cnnvd_affver.append(aff_versions)
        cnnvd_level.append(level)
        cnnvd_desc.append(descs)
        cnnvd_patches.append(patches)
        cnnvd_patches_links.append(patches_links)
        update_time.append(time)
        # print(patches)

    store_data(tag + '.csv', cnnvd_ids, cve_ids, cnnvd_titles, cnnvd_urls, cnnvd_level, cnnvd_affver, cnnvd_patches, cnnvd_patches_links, update_time, tag)


def main():
    for tag in tags:
        cnnvd(tag)
    # cnnvd('Apache Hadoop')


if __name__ == '__main__':
    main()
    
