
rule j3ec_69ad2960594af9b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.69ad2960594af9b2"
     cluster="j3ec.69ad2960594af9b2"
     cluster_size="119"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector ayazmhii infector"
     md5_hashes="['029393ed3b8b98638a2083ae46366915','02dd65d374e077762161b2c99923296b','1ebfa636a38a31dfffd08919e230b11e']"

   strings:
      $hex_string = { 0e0302f3a4088a0688074746e2f804acaae2fc080302ffe40254c3048bc4ffe0c745302a2e657866c7453465008d455c508d5d3053ff95b00100004085c00f84 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
