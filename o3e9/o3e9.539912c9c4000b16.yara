import "hash"

rule o3e9_539912c9c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.539912c9c4000b16"
     cluster="o3e9.539912c9c4000b16"
     cluster_size="1433 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bdadaaf pckeeper sality"
     md5_hashes="['4dcbcc48e8bba326e9563b39260d8887', '73b03816f901268f1059c4ee3da38175', '588fd3d4a727c57440f42360ad7525fe']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1392640,1024) == "526663c508f12b28e28f913408e73b90"
}

