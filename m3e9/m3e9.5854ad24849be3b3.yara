import "hash"

rule m3e9_5854ad24849be3b3
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5854ad24849be3b3"
     cluster="m3e9.5854ad24849be3b3"
     cluster_size="350 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef diple"
     md5_hashes="['ca6ff4358a5edcb8f1f455ad90954807', 'b2a3ef7c2c17a173119e001b6ef3628c', 'a06562bf258c909efac3af41525dab9f']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(224256,1024) == "7c94c957c8569a369a9dc8b86dd0901d"
}

