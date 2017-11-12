import "hash"

rule n3e9_14c1a64bc3690932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.14c1a64bc3690932"
     cluster="n3e9.14c1a64bc3690932"
     cluster_size="403 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c55c7e8fa0292d366341ce9618150305', 'ba37e46b45e12525a84a66cb54b54b09', '5772184ced9e3b068bef9386c7503a52']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(531456,1088) == "f79c53eb77ac1204e13806116c81daf6"
}

