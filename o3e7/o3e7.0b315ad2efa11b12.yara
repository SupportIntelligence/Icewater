import "hash"

rule o3e7_0b315ad2efa11b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.0b315ad2efa11b12"
     cluster="o3e7.0b315ad2efa11b12"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="dlboost malicious engine"
     md5_hashes="['7657bbb7e749d8fc0c6d3899950613a8', '01450d4b3061856d2e10aab331adf9a6', '01450d4b3061856d2e10aab331adf9a6']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2328576,1029) == "dc830474e814e64b8aea987f2eac5030"
}

