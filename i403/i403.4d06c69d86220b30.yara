
rule i403_4d06c69d86220b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i403.4d06c69d86220b30"
     cluster="i403.4d06c69d86220b30"
     cluster_size="385"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rootkit small zusy"
     md5_hashes="['025b5f7b1135ab108b0dc60b3e6117d9','03418cdad41d8686d71dbe718ebe8e2e','08d3ba408274a544540486e8871a5a95']"

   strings:
      $hex_string = { a1024d6d47657453797374656d526f7574696e6541646472657373001d0452746c496e6974556e69636f6465537472696e6700007d0350734c6f6f6b75705072 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
