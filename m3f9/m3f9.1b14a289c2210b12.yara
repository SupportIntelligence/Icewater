import "hash"

rule m3f9_1b14a289c2210b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.1b14a289c2210b12"
     cluster="m3f9.1b14a289c2210b12"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zbot malicious kryptik"
     md5_hashes="['39a7de5c83fec3b806c4802d4bdd7316', '7dd0093dfdce65cc39aaa1c8f89322e8', '7dd0093dfdce65cc39aaa1c8f89322e8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(66048,1024) == "36ad98247628c5d4ec7f137d36797e57"
}

