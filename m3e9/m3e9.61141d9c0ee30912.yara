import "hash"

rule m3e9_61141d9c0ee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61141d9c0ee30912"
     cluster="m3e9.61141d9c0ee30912"
     cluster_size="142 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef autorun"
     md5_hashes="['acef62d38a31689fadcda559f32c3ac6', 'afd12ac0e65b6be1afd27af630927033', 'dedd3d880fb58be292b54c6dd101e316']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(69632,1024) == "0f79d8f2f9e604ac05baa38c9b9f0b14"
}

