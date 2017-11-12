import "hash"

rule n3e9_4914d3a9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4914d3a9c4000b32"
     cluster="n3e9.4914d3a9c4000b32"
     cluster_size="830 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a8b7331f582dc21ec002c08c56a5d3f5', 'c42d51a029072efcb480d033ccb08402', '1450d93f5d4eec1ec55198f73be5ce91']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(3219,1097) == "9dbcdb80646b5cb4bf3285436fc29f56"
}

