import "hash"

rule k3e9_6956fa7b61246796
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6956fa7b61246796"
     cluster="k3e9.6956fa7b61246796"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['bdf659e226c2ba6504b17e3edc58f55a', '8c63e377881e468d273fb429fa3926cb', '8c63e377881e468d273fb429fa3926cb']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18723,1041) == "f56d85d5e204fe8b22ff7546c043c8f3"
}

