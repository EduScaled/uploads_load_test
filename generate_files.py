for val in [1,3,5,10,100,300]: 
  f = open("files_to_upload/{}mb".format(val),"wb")
  f.seek(val * 1024 * 1024 - 1)
  f.write(b"\0")
  f.close()
