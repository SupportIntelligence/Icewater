
rule k3f7_249d399bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.249d399bc6220b32"
     cluster="k3f7.249d399bc6220b32"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script fakejquery"
     md5_hashes="['360331d10d28f9a7a45c393f33207918','5aa39e98043c880199dab2dccd1f9edf','e937a92a937da067279c3063dc39ac17']"

   strings:
      $hex_string = { 6155524c28292c63213d3d64293b6361736522646976657273697479223a72657475726e20692e66696c6c54657874286a2835353335362c3537323231292c30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
