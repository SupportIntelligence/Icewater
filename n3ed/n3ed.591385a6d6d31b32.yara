import "hash"

rule n3ed_591385a6d6d31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a6d6d31b32"
     cluster="n3ed.591385a6d6d31b32"
     cluster_size="327 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="xpaj blcbg bscope"
     md5_hashes="['edb47e59cbf3e4403ddce1ea10ec1200', 'd62516d49f63db491fdb60e72c6831d6', 'b3f512c588f379f5f8fa595db5eb148c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(418756,1036) == "210f6608b2efbfbe03110188284f4477"
}

