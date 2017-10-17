import "hash"

rule k3e9_6b64d34f8a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8a6b5912"
     cluster="k3e9.6b64d34f8a6b5912"
     cluster_size="383 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['bc6991cf04365649e6d091d1bb97f466', 'e784d009a5a786a16c93965bc6f5e024', 'ca5d94dd40f2c0f662a119beb07add62']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17576,1036) == "c9de54f1454eda93417385069e74c982"
}

