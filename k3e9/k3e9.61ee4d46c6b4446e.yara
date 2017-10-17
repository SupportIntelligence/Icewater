import "hash"

rule k3e9_61ee4d46c6b4446e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61ee4d46c6b4446e"
     cluster="k3e9.61ee4d46c6b4446e"
     cluster_size="30 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d47a8d94bc581b1f31809be119e095d0', 'd405b19a09f2b63b19763917b4e6a9d0', 'd47a8d94bc581b1f31809be119e095d0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

