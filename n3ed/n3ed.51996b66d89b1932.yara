
rule n3ed_51996b66d89b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b66d89b1932"
     cluster="n3ed.51996b66d89b1932"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['001e5be911072a3133741f9665e24c15','134e6bbc4c8875e01eae6c53e449c63e','db7c3c6a2f8d2a7f30762a91913af9c0']"

   strings:
      $hex_string = { e430143177319b3117348c34ce34b435bb35c635cf357037a43712384d3803390a396c39ae39d43a073b843bc13bcc3ce53cf63c0f3d273d403d943d343e513f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
