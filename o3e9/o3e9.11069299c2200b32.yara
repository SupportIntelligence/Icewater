import "hash"

rule o3e9_11069299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.11069299c2200b32"
     cluster="o3e9.11069299c2200b32"
     cluster_size="315 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy trojandropper bjrqpg"
     md5_hashes="['3e35027d0cb0875f02d57faa72099ae1', 'cb7f1e0326330152afa3d1cd2278f3e9', '27d385fdc43664d25f727f4c60971875']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1826816,1024) == "a8bf51f76a68811b2b8c67873449dc0d"
}

