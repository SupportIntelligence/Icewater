import "hash"

rule n3e9_16bab949c0000954
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16bab949c0000954"
     cluster="n3e9.16bab949c0000954"
     cluster_size="1085 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['339bb57098b677fd331f46d89180a8c9', 'a0e1028809cd2e26ed8a23ff35d3cd3b', '83536581f79f67cf83c9fdeac3afcc4c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(87552,1024) == "28440c8fae03dcac5981bfcc2a3cd656"
}

