import "hash"

rule n3e9_3a1ebec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3a1ebec1c4000b12"
     cluster="n3e9.3a1ebec1c4000b12"
     cluster_size="264 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="unruy backdoor banito"
     md5_hashes="['421accdfc38e8b532b28927b88aad3c2', '256babac1b2110113b792e2e6ee24156', 'd1213e5e7c219d291c176e75db1e8c37']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(324608,1024) == "5148818efca137413d3c7dbb35b47da9"
}

