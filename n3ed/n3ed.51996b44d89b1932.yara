
rule n3ed_51996b44d89b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b44d89b1932"
     cluster="n3ed.51996b44d89b1932"
     cluster_size="36"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['0dc9301c4583a0b6892ee26cfe87592d','2056344012f82094a803dfacd6c44eba','bfee39c090edc6adca3eae55970b7e76']"

   strings:
      $hex_string = { e430143177319b3117348c34ce34b435bb35c635cf357037a43712384d3803390a396c39ae39d43a073b843bc13bcc3ce53cf63c0f3d273d403d943d343e513f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
