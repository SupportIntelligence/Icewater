import "hash"

rule n3e9_119844b9ca220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.119844b9ca220b32"
     cluster="n3e9.119844b9ca220b32"
     cluster_size="220 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="yakes crypt kryptik"
     md5_hashes="['086a40fa54f11755eb7ba9443e186ff8', 'a0a19004cd8bd6cda3d061a7ea6b7953', '7a707c10f3b7905d9a8f57fde0a8d967']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(462848,1024) == "624eb1ed49daa3cc53b7829930e3d04f"
}

