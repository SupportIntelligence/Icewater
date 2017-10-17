import "hash"

rule n3ed_15f0ca6ba6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.15f0ca6ba6220912"
     cluster="n3ed.15f0ca6ba6220912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['68f7a400d2f99031b582e81cd6f1ac57', '38ee4c0e42008097696cc1ec4386090f', '68f7a400d2f99031b582e81cd6f1ac57']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(175616,1024) == "7858e5bdec228257b0fded716f7e177d"
}

