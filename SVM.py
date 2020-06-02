# coding: utf-8

import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn import svm

import urllib
import time
import pickle
import html


class WAF(object):

    def __init__(self):
        good_query_list = self.get_query_list('Data/goodqueries.txt')
        bad_query_list = self.get_query_list('Data/badqueries.txt')

        # 好的标记0，坏的标记1
        good_y = [0 for i in range(0, len(good_query_list))]
        bad_y = [1 for i in range(0, len(bad_query_list))]

        queries = bad_query_list + good_query_list
        y = bad_y + good_y

        # converting data to vectors  定义矢量化实例
        self.vectorizer = TfidfVectorizer(tokenizer=self.get_ngrams)

        # 把不规律的文本字符串列表转换成规律的 ( [i,j],tdidf值) 的矩阵X
        X = self.vectorizer.fit_transform(queries)

        # 使用 train_test_split 分割 X y 列表
        # X_train矩阵的数目对应 y_train列表的数目(一一对应)  -->> 用来训练模型
        # X_test矩阵的数目对应 	 (一一对应) -->> 用来测试模型的准确性
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.95, random_state=42)

        self.clf = svm.SVC(kernel='rbf', C=1E6, gamma='auto')
        self.clf.fit(X_train, y_train)


        # 使用测试值对模型的准确度进行计算
        print('模型的准确度:{}'.format(self.clf.score(X_test[0:5000], y_test[0:5000])))

    # 对 新的请求列表进行预测
    def predict(self, new_queries):
        new_queries = [urllib.parse.unquote(url) for url in new_queries]
        X_predict = self.vectorizer.transform(new_queries)
        res = self.clf.predict(X_predict)
        res_list = []
        for q, r in zip(new_queries, res):
            tmp = '正常请求' if r == 0 else '恶意请求'
            q_entity = html.escape(q)
            res_list.append({'url': q_entity, 'res': tmp})
        print("预测的结果列表:{}".format(str(res_list)))
        return res_list

    # 得到文本中的请求列表
    def get_query_list(self, filename):
        directory = str(os.getcwd())
        filepath = directory + "/" + filename
        data = open(filepath, 'r', encoding='utf-8').readlines()
        query_list = []
        for d in data:
            d = str(urllib.parse.unquote(d))  # converting url encoded data to simple string
            query_list.append(d)
        return list(set(query_list))

    # tokenizer function, this will make 3 grams of each query
    def get_ngrams(self, query):
        tempQuery = str(query)
        ngrams = []
        for i in range(0, len(tempQuery) - 3):
            ngrams.append(tempQuery[i:i + 3])
        return ngrams


if __name__ == '__main__':
    w = WAF()
    with open('Model/svm.pickle', 'wb') as output:
        pickle.dump(w, output)

    with open('Model/svm.pickle', 'rb') as input:
        w = pickle.load(input)

    w.predict(['www.foo.com/id=1<script>alert(1)</script>',
               'www.foo.com/name=admin\' or 1=1',
               'abc.com/admin.php',
               '"><svg onload=confirm(1)>',
               'test/q=<a href="javascript:confirm(1)>',
               'q=../etc/passwd'])