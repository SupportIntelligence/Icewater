import "hash"

rule k3e9_493e7324dda31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e7324dda31916"
     cluster="k3e9.493e7324dda31916"
     cluster_size="102 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ab3ec9004eab532f409a4d0e6f7655dd', '96f0f05fee6c3d5128a90e522665dd11', '0c65c5c076c5fb52bf40bd41c2dff309']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15872,1024) == "2be0f6e1890b843287e156fe1877e9d8"
}

