
rule k3ec_36cd16b8dad18b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.36cd16b8dad18b12"
     cluster="k3ec.36cd16b8dad18b12"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="resur senna malicious"
     md5_hashes="['a53a51b810a25c48476519a7c49a8c68','b1b9a9b8eb179582ee05b1dd9e933f88','e3e654b3ec58456b4b58c8373d4948a5']"

   strings:
      $hex_string = { 0583f804750a8d45fc50e80e00000059fec380fb1a72d46a01585bc9c3558bec81ec5c0200008b55085356578bfa83c9ff33c0f2aef7d149807c11ff5c7428bf }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
