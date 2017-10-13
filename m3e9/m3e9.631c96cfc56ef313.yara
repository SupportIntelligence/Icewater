import "hash"

rule m3e9_631c96cfc56ef313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c96cfc56ef313"
     cluster="m3e9.631c96cfc56ef313"
     cluster_size="57 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['c7909b737ffe2e02c098f035c4fbeea2', '9e08d2c3593715611dd16ec5c2021754', 'acf7b9f03287c9eb2c8ce94e5e5620f7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(87552,1024) == "28440c8fae03dcac5981bfcc2a3cd656"
}

