import "hash"

rule m3e9_196a10963a631132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.196a10963a631132"
     cluster="m3e9.196a10963a631132"
     cluster_size="90 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus jorik vbobfus"
     md5_hashes="['c29ada053e2f91bf724e7274f35d5cf2', 'a0260b3b70e3ae3743ebeca7a22f1681', 'a709e7b49627b0d3906feb06b7281441']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(137216,1024) == "0cf457b405b0975823abd64666c18892"
}

