import "hash"

rule n3f0_231b1246c8579b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.231b1246c8579b16"
     cluster="n3f0.231b1246c8579b16"
     cluster_size="130 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ccpk malicious"
     md5_hashes="['d677128af84ffa4528c429d3c54832c2', 'de288d1e89fcc0a028829632cc339fa8', 'bd686338524989737c3a3b407822c299']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(257536,1280) == "50bd3647c518c2cc4b265b800b3315c9"
}

