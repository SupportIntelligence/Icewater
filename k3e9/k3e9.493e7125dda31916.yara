import "hash"

rule k3e9_493e7125dda31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e7125dda31916"
     cluster="k3e9.493e7125dda31916"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['317206a0b3655643606c3a03fb4350e9', '3bb62516be2570cb1c5ac3b4b7aed62e', '729c8e0156e6a4754a355032870e8310']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15872,1024) == "2be0f6e1890b843287e156fe1877e9d8"
}

