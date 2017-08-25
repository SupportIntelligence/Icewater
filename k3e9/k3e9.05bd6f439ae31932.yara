import "hash"

rule k3e9_05bd6f439ae31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05bd6f439ae31932"
     cluster="k3e9.05bd6f439ae31932"
     cluster_size="1253 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="fdld nitol dropped"
     md5_hashes="['2a009aaa1523e3ad11b52ab5627bdb3d', '056c8559053dfc5664b0c564624de882', '328d681e435f7d14701c060eaddb1c85']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "c5999b2aae920e6fc825cd5123f52641"
}

