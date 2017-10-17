import "hash"

rule k3e9_42146134dda30b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.42146134dda30b10"
     cluster="k3e9.42146134dda30b10"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['56cc186f9d3f528fb556d1db47786f6d', '0b548993c0e7c9ddf9ef55d126042c3d', '56cc186f9d3f528fb556d1db47786f6d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5236,1053) == "f906a3bcdc2f7c6cc54ba5e3cf5278e7"
}

