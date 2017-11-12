import "hash"

rule n3e9_4914d2c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4914d2c9c4000b32"
     cluster="n3e9.4914d2c9c4000b32"
     cluster_size="1175 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a65468d4a98148016ee8a45d5a4e9782', 'a92a28885358e402034e61ab4b6d6056', 'a2f87eafdbde6599a19d96f2ceee5b5a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(3219,1097) == "9dbcdb80646b5cb4bf3285436fc29f56"
}

