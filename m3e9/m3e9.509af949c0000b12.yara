import "hash"

rule m3e9_509af949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.509af949c0000b12"
     cluster="m3e9.509af949c0000b12"
     cluster_size="208 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbna vbran"
     md5_hashes="['d216b054cc88071097dad21630370aa2', 'd75fa9229b89ded0756f834644855e36', 'cca77d52935d55ceb09964de5a4f503b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(49152,1024) == "c9c46814be33ffaa75d8cac19f5fd570"
}

