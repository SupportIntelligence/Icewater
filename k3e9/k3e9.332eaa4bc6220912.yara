import "hash"

rule k3e9_332eaa4bc6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.332eaa4bc6220912"
     cluster="k3e9.332eaa4bc6220912"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['3cf6fe0957fdb52fb292bc6de7f4c987', '8c5a810a4c57585d7cbe45b0ec590429', '8c5a810a4c57585d7cbe45b0ec590429']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "bafdc1c966710908612de8a0df7c0810"
}

