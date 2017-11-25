
rule i3f7_15b0e9b9c976e131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3f7.15b0e9b9c976e131"
     cluster="i3f7.15b0e9b9c976e131"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['4bc9fde149b878a7dbc3409b2880eceb','71feaa34bce3149f4f43a97a46afe69b','f88fe26300a4d83a1a46a952e0735ba3']"

   strings:
      $hex_string = { 682e72616e646f6d28292b0d0a222720616c743d2727207469746c653d274c697665496e7465726e65743a20cfeeeae0e7e0edee20f7e8f1ebee20eff0eef1ec }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
