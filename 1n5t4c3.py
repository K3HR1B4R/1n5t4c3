import hack

print """
1N5T4C3
OZELLIKLER:
1-WordList Olusturucu
2-Dork Maker
"""
b=hack.WordList()
a=hack.DorkMake()
c=a.make
d=b.run(input())
sayi = input("birini secin")

if sayi == 1:
    print"""
################################
#                              #
#    WordList Olusturucu       #
#        By 1N5T4C3            #
#                              #
################################
"""
    a.c(input())
else:
    print"""
################################
#                              #
#         Dork Maker           #
#         By 1N5T4C3           #
#                              #
################################
"""
    b.d
