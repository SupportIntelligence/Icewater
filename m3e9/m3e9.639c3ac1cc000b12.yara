import "hash"

rule m3e9_639c3ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.639c3ac1cc000b12"
     cluster="m3e9.639c3ac1cc000b12"
     cluster_size="681 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['492c2a21facd0c66c4aa8af57d9bda09', '0ee87c9f262cb577df3c78c4406284ae', '6ef1083f96536e3713b1db5b297cd581']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

