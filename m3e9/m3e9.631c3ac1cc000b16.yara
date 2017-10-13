import "hash"

rule m3e9_631c3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c3ac1cc000b16"
     cluster="m3e9.631c3ac1cc000b16"
     cluster_size="1137 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['0c2355ed1ef39f1221502f0353ce3a33', '0434dcf09f6b6ee2ffdb3b7ad96b9a6d', '60296ef8f5de3f3ab36ac60225e63b13']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

