import "hash"

rule m3ed_521c03b919464d56
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.521c03b919464d56"
     cluster="m3ed.521c03b919464d56"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['418e82f0e24b474461f9b1b29f52763e', 'bc5c655fed59faa904186df724d3dec2', '0d9c0f0e21e5e21fc198e3f540633825']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

