import "hash"

rule k3e9_6335ba56d9bb1b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6335ba56d9bb1b32"
     cluster="k3e9.6335ba56d9bb1b32"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['bdd439580614ea267b42f3de39ddea6d', 'ee38cd678e0270dc174b9b467ce98a33', 'ee1c8acfc724879a445a9b63a48722e0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,1280) == "2c4c3f190a53a22c484f2b4eb790033f"
}

