import "hash"

rule m3e9_5296968be6600b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5296968be6600b12"
     cluster="m3e9.5296968be6600b12"
     cluster_size="58 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus symmi vbkrypt"
     md5_hashes="['6d02221e012bf15af26b954217693d07', 'd202ec0e910a7534f870e1dd0a3cc0a5', '8a7561fe1b0da7bac2188a8e1fd86bb4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(20480,1024) == "dd45666939b93642cf543ff4a69ec880"
}

