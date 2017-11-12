import "hash"

rule n3e9_29a8944b46220916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29a8944b46220916"
     cluster="n3e9.29a8944b46220916"
     cluster_size="198 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious heuristic attribute"
     md5_hashes="['b68be3a0ae283ed028b529edb8b67e88', 'fe7eeb7751fa44c947079c8deb8d97ca', 'b68be3a0ae283ed028b529edb8b67e88']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(217088,1152) == "56891bbe325eab0c77c71875dc16efff"
}

