import "hash"

rule m3e9_6114dab0faa10932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6114dab0faa10932"
     cluster="m3e9.6114dab0faa10932"
     cluster_size="128 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sirefef vobfus diple"
     md5_hashes="['e6dde575a32816f8706129c03d65f3d6', 'c7218ba0b4c56f4af8c12c6e1d46b32d', 'cb20afd621405049a654544a6114010c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61440,1024) == "2257ea637f9c40f42905338f90c89ca3"
}

