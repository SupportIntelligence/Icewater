import "hash"

rule o3e9_52993834deab1b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.52993834deab1b32"
     cluster="o3e9.52993834deab1b32"
     cluster_size="60 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="linkury zusy bdff"
     md5_hashes="['937ba838f4486a5e00d05c1c52a638ae', '0b9dcbea805d4a6e8daa02515e1b8bd9', '555ab18ce879bfd6f0cf5e604a7c6cd3']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2721120,1044) == "7ed2738526c85bdece26d69829235672"
}

