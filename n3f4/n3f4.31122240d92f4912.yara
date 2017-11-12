
rule n3f4_31122240d92f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.31122240d92f4912"
     cluster="n3f4.31122240d92f4912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik malicious tuto"
     md5_hashes="['2d07ab898cff60fa35a782e70008d100','3d0370f2c3ff091eb0446d9286af0e52','ac2e527f157c40102e24d01cc0e77e34']"

   strings:
      $hex_string = { 626d3966614531426b724743486a5176775a4934694c7653337149566750736750756f57486474456d4e7a754b526f4346783550584e7961702f635544654d2b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
