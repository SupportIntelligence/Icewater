
rule n3ed_51996b66dda31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b66dda31932"
     cluster="n3ed.51996b66dda31932"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['287ab81e8714d91b79c019bd83994b0b','31551c1fbbc6893a783daabdcd677adb','ab3caa3b68443fd0647b58ee08d7f1e6']"

   strings:
      $hex_string = { e430143177319b3117348c34ce34b435bb35c635cf357037a43712384d3803390a396c39ae39d43a073b843bc13bcc3ce53cf63c0f3d273d403d943d343e513f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
