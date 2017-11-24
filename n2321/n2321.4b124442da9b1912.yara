
rule n2321_4b124442da9b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.4b124442da9b1912"
     cluster="n2321.4b124442da9b1912"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softpulse bundler riskware"
     md5_hashes="['025ec4aa5a3abfb0389b9a56f240f0fa','25246ddc61ba4a0e268978539193f4cb','f7cc5430af8c9b3294b08e361bb08f49']"

   strings:
      $hex_string = { ac850417f133d47c0677e9da63685981ba11e56e6dfa83076cfc199b8fb974511e294598ca50c9c0a2209ffe919cc35b7b5fb6bc5dff40deae27021bc1df238d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
