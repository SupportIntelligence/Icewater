
rule n2321_339a6886dcebd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.339a6886dcebd912"
     cluster="n2321.339a6886dcebd912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['12f488d730ce52ef67eb125d581cc4c0','13570b2012729b3f80293415ce05288f','de29c53a5c3d33f0237b889c6cc02d2b']"

   strings:
      $hex_string = { ee18f18372e0493953a702b6ceb2c32ba0330c10e97170ec3da1edcc068457b411aed20ecd8a8cb0acbf5941cfca52ded920a317c5bc6b94ef66c16df96e56d6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
