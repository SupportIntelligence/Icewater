import "hash"

rule n3e9_13995b69c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13995b69c8800b32"
     cluster="n3e9.13995b69c8800b32"
     cluster_size="61 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['baf85c9ca824fec02ef2c537a19edae4', '03bc073e6150565cfcc5305e6c7ab396', '3c5a2b0ad8bb3158bf7ce3c311982124']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(161860,1026) == "56c00bba8a5f0944121279b68db8e677"
}

