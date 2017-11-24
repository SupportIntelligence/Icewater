
rule m3e9_3a5b3599c2200b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5b3599c2200b14"
     cluster="m3e9.3a5b3599c2200b14"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['993c0e489158e04cfff5ae72ea68b875','a6a992cb5356af1a4964a79cbd3e30d3','d908f8d0d818ffad39d1a4bd688a23ee']"

   strings:
      $hex_string = { e1b586cefe7812a6bf454e491087d0625a008c83d9d1568535797704747e988aad00efa72d89385e1071191a4f44f5bab38ad522a4ae31421c27c221e5720d9d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
