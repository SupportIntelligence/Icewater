
rule n26c0_79b9c6c4d912d11a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.79b9c6c4d912d11a"
     cluster="n26c0.79b9c6c4d912d11a"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious arre chapak"
     md5_hashes="['e4da83143e8f790a7a1c9d5455384583015d1198','d47ddf6831b19bc2702b914080e82799fbbea988','ea73e2219e4ad6b3e272e728e95301261209a1c2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.79b9c6c4d912d11a"

   strings:
      $hex_string = { baf8c54e005683e01f33f66a20592bc8b8d4c54e00d3ce33c93335705044003bd01bd283e2f783c2094189308d40043bca75f65ec3558bec807d0800752756be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
