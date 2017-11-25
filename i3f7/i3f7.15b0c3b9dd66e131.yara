
rule i3f7_15b0c3b9dd66e131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3f7.15b0c3b9dd66e131"
     cluster="i3f7.15b0c3b9dd66e131"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['0afb314ce817905b0b1593edd01dfc06','78030cb2c6dfbbf07abf1d48e20b5d98','e13a472498d4da5f30c22f04ed411d76']"

   strings:
      $hex_string = { 682e72616e646f6d28292b0d0a222720616c743d2727207469746c653d274c697665496e7465726e65743a20cfeeeae0e7e0edee20f7e8f1ebee20eff0eef1ec }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
