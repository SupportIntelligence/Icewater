import "hash"

rule k3e9_6b64d34f9b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9b4b4912"
     cluster="k3e9.6b64d34f9b4b4912"
     cluster_size="79 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['de844b5f712e88e75aeb97cc4907927d', 'c4cca48959d0a2c5a0156d488a5350c6', 'c7a3031ca03f43f0b00df76e346ce7d5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17576,1036) == "c9de54f1454eda93417385069e74c982"
}

