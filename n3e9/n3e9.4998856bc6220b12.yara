
rule n3e9_4998856bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4998856bc6220b12"
     cluster="n3e9.4998856bc6220b12"
     cluster_size="73"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="loadmoney krypt cobra"
     md5_hashes="['0083ea1724e448bc0ddba6759ce0a123','08879e828728c87c255c28440215b0ae','42a2517b69b55658b4ea3e32bfe8e8b6']"

   strings:
      $hex_string = { 41646d696e6973747261746f72222075694163636573733d2266616c7365223e3c2f726571756573746564457865637574696f6e4c6576656c3e0a3c2f726571 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
