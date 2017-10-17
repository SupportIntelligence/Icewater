import "hash"

rule n3f0_231b16c6c8479b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.231b16c6c8479b16"
     cluster="n3f0.231b16c6c8479b16"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ccpk malicious"
     md5_hashes="['a2233f4f5b0d082c70bd8614ce9427bd', 'a2233f4f5b0d082c70bd8614ce9427bd', 'c3eef54005b41aae8dc1592a74214829']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(257536,1280) == "50bd3647c518c2cc4b265b800b3315c9"
}

