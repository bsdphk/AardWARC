

import sys

r1 = []
r2 = []

for i in sys.stdin:
	j = i.replace(':', ' ').split()
	if not j:
		continue
	if j[0] in ('File', 'Function'):
		subj = j
	elif j[0] == 'Lines':
		assert j[2][-1] == '%'
		j[2] = j[2][:-1]
		p = float(j[2])
		l = int(j[4])
		m = (100.0 - p) * l * .01
		if subj[0] == 'File':
			r1.append([m, p, l, subj[0], subj[1]])
		else:
			r2.append([m, p, l, subj[0], subj[1]])

for r in (r1, r2):
	print('Percent Lines Missing')
	print('=' * 60)
	r.sort()
	tl = 0
	tm = 0
	for m, p,l,t,n in r:
		tl += l
		tm += m
		print("%6.2f" % p, "  %4d" % l, "   %4d" % m, "  ", t, n)
	print("")

print('Percent Lines Missing')
print('-' * 60)
print("%6.2f" % (100.0 * (tl-tm) / tl), "  %4d" % tl, "   %4d" % tm)
print('-' * 60)

