import "hash"

rule k3e9_616d4156fa611132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.616d4156fa611132"
     cluster="k3e9.616d4156fa611132"
     cluster_size="3100 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre waski generickd"
     md5_hashes="['040f48fb698266041c61f66b82931978', '0ec5389f2ba9dc77f79f9def8fdf9b4e', '666ff0c90bc7ccf96e4275dc2035157f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "a8a8e794c969ee03d14a49581e6e0204"
}

