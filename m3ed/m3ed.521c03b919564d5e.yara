import "hash"

rule m3ed_521c03b919564d5e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.521c03b919564d5e"
     cluster="m3ed.521c03b919564d5e"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['198e79b92eab2f2945b1e230246b3304', 'c7bb47a7d803914fbae28bd83f825d11', 'e6168bb36e61ae97ab6e1c9c973cb66a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

