import "hash"

rule k3e9_6335ba5edcbb1b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6335ba5edcbb1b32"
     cluster="k3e9.6335ba5edcbb1b32"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a3a4aa62dae15f140408ff90172cdf95', 'aaeead56f851648006c6a02ca34c5767', 'b086f9fee269ad597ac910b14c845556']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,1280) == "2c4c3f190a53a22c484f2b4eb790033f"
}

