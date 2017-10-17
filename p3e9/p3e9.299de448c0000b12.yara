import "hash"

rule p3e9_299de448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.299de448c0000b12"
     cluster="p3e9.299de448c0000b12"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hacktool cheatengine malicious"
     md5_hashes="['a3cd4d74236e27353d5e12cbe542610f', 'a3cd4d74236e27353d5e12cbe542610f', 'a7cfcd3404b3e8c478d797f9f9bd5137']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(46080,1024) == "aa1f57a63e6e3da300b70d290186a1bb"
}

