import "hash"

rule n3e9_31ba292bda0bd932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ba292bda0bd932"
     cluster="n3e9.31ba292bda0bd932"
     cluster_size="393 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor darkkomet fynloski"
     md5_hashes="['b5e97aff17c9a1ff24b8dc18329cd63f', '7a068353e63784e1f3c729b0db218e42', '0c5605f25d30cf78958eab0b1096db0d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(630272,1024) == "b4f185c39e9f1bdee3a3d63012d57f58"
}

