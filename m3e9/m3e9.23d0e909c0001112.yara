import "hash"

rule m3e9_23d0e909c0001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.23d0e909c0001112"
     cluster="m3e9.23d0e909c0001112"
     cluster_size="11975 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="upatre kryptik doxv"
     md5_hashes="['0a90b698e0681a7e8bb0eac50aca8186', '1212d262a341ab45d71d33924f0e4a50', '0569d4f113f9e6916195b9688a8c9474']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(58880,1024) == "645b0b84b3cbf6dd9d13be9a3884ba41"
}

