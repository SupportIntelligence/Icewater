import "hash"

rule n3e9_51306934dbd30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.51306934dbd30b32"
     cluster="n3e9.51306934dbd30b32"
     cluster_size="276 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['f3dcdb06ce47deafbf5d782b3b6a5c4a', '978a1719ac1d51a0f2872bff92ecd8f6', 'ba1e70bb6a8935c70d22d3c8855c44dd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(202240,1024) == "a0a6e296be36ab062c3ec5bce57f1d3f"
}

