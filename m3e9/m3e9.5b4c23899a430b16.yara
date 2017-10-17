import "hash"

rule m3e9_5b4c23899a430b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5b4c23899a430b16"
     cluster="m3e9.5b4c23899a430b16"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="floxif pioneer fixflo"
     md5_hashes="['5ccd814127ebfc19b0c8fa26465f1e34', '948789bf88e587332b46e2c0962345fe', '948789bf88e587332b46e2c0962345fe']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138752,1024) == "80d850aa1c13fc703e524f68055c8e86"
}

