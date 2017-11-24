
rule k2321_0969b962d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0969b962d9eb1912"
     cluster="k2321.0969b962d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['246d2680cf4fe4a0beb73228a6ca180e','3be3c10f5cf3497ca1c9a102ab2de9d0','8d804999d09b918c7c2c138f2e8b26c9']"

   strings:
      $hex_string = { aa4d3e465a18174a67e6a5a6d6a23d29e6be1f3802a460530ff1693cfa14bb1cc34b83a498baf2106dc8e27c1d2bda908d850bf69499f96bb18f162754950c9a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
