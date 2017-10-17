import "hash"

rule m3ed_114f5ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.114f5ac1c4000b12"
     cluster="m3ed.114f5ac1c4000b12"
     cluster_size="70 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ageneric heuristic malicious"
     md5_hashes="['3bd3426dcbb20cb249c8fd6128128577', 'd9dc71b729364e709ba5b9a4c1788e8b', 'a1073f042fd22288f25f997b22325a64']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(74240,1536) == "dfda9d7ba6e18766ed7cb66b7ecf68be"
}

