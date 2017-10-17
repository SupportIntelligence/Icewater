import "hash"

rule n3e9_216d59e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.216d59e9c8800b12"
     cluster="n3e9.216d59e9c8800b12"
     cluster_size="37 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virtob virut virux"
     md5_hashes="['b223978d2a73256929faf8947b147076', 'df1b249bd64d669feb8ea578ba9f5e73', 'baa3816bf5d11bf915a6d161357595e6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(42688,1024) == "63796a380be8d2288cb3009b4efb918f"
}

