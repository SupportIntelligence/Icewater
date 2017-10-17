import "hash"

rule m3e9_6115a848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6115a848c0000b12"
     cluster="m3e9.6115a848c0000b12"
     cluster_size="1297 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['a6051a092cb25a9f817168d432ca6f4f', '673bc087b96d98d8fba067ac9b312214', 'a84e041971979df24cbe1d0485917a3a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57856,1024) == "75f3c9fd975d819550e3e61fa3b0e2b0"
}

