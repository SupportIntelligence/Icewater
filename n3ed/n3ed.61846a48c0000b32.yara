import "hash"

rule n3ed_61846a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.61846a48c0000b32"
     cluster="n3ed.61846a48c0000b32"
     cluster_size="60 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['68f7b53927aec0aa7900fcc3aec97b1c', '41af68977557dbc8fb6709c65b05ec56', '590a71d60f915d463fc4ed54e35b9d6d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(153294,1126) == "ba84523659dc6aaade6ed741f8bb367b"
}

