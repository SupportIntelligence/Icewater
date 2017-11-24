
rule n3e9_0b124422da9b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b124422da9b1912"
     cluster="n3e9.0b124422da9b1912"
     cluster_size="22"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softpulse bundler riskware"
     md5_hashes="['1d6d9e49cd7e90cf5a608fbb37667251','2e66b60a96166e979f9da096ade3c7fc','b4de719caa67c934d26526daf76cdc09']"

   strings:
      $hex_string = { ac850417f133d47c0677e9da63685981ba11e56e6dfa83076cfc199b8fb974511e294598ca50c9c0a2209ffe919cc35b7b5fb6bc5dff40deae27021bc1df238d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
