
rule n26c0_79b9c4d4d932d11a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.79b9c4d4d932d11a"
     cluster="n26c0.79b9c4d4d932d11a"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious heuristic prepscram"
     md5_hashes="['35fa672afe62b562027c19c7ff2b47b76eb37efb','701b057859263ec52a2382c7d9ea7e43431281e6','24211e531d5953636adb059b24eac6c2e7a34b79']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.79b9c4d4d932d11a"

   strings:
      $hex_string = { baf8c54e005683e01f33f66a20592bc8b8d4c54e00d3ce33c93335705044003bd01bd283e2f783c2094189308d40043bca75f65ec3558bec807d0800752756be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
