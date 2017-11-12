import "hash"

rule n3ed_591385a6ddeb1b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a6ddeb1b32"
     cluster="n3ed.591385a6ddeb1b32"
     cluster_size="261 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b71b3982b0b61213f851bc6696215c57', '988d1609e2cba53255db294ae48dafe9', 'c1540382ef740bfd99bbe186c350d262']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

