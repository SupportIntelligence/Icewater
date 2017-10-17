import "hash"

rule n3f0_231b1046c8579b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.231b1046c8579b16"
     cluster="n3f0.231b1046c8579b16"
     cluster_size="38 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ccpk malicious"
     md5_hashes="['cdd5232ee523b0dab3e2bb4a905c4be1', 'bab731aee3b2c4fc39129b748fbdfd2d', 'b4f7e50fba66232c46d2e3cebf3c01c4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(257536,1280) == "50bd3647c518c2cc4b265b800b3315c9"
}

