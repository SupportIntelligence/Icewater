import "hash"

rule m3e9_211db48fc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.211db48fc2220b32"
     cluster="m3e9.211db48fc2220b32"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran malicious"
     md5_hashes="['e7e8a500db9692aa4fa07111972f27e9', 'b2fc7bbf968618069fd090be09e5e6e7', 'a2fd77d32d6d1fca961fc7cb6ad8f2aa']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(107520,1024) == "8cb42e7227c47718daab6702451d31db"
}

