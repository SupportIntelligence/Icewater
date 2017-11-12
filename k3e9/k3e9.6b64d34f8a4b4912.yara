import "hash"

rule k3e9_6b64d34f8a4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8a4b4912"
     cluster="k3e9.6b64d34f8a4b4912"
     cluster_size="108 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['a26d7c89906f5d5e385c2826a50818d5', '60d81c1e233989ac83d33034cae97aab', 'e4488d1b4e9a6bf82bf86ea8bebc811b']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(6180,1036) == "2b4289c8af774f0b1076619ad1925bff"
}

