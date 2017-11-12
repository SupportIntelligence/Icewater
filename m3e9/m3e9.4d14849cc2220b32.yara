import "hash"

rule m3e9_4d14849cc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d14849cc2220b32"
     cluster="m3e9.4d14849cc2220b32"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus graftor vbkrypt"
     md5_hashes="['cfb71dd61f2c087976a0ba453300ba85', '4f029450331810188216db3f411b7732', 'cfb71dd61f2c087976a0ba453300ba85']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(76800,1024) == "f1928b49bb657f067d8733a617468e09"
}

