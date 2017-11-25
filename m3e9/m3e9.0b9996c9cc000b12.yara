
rule m3e9_0b9996c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b9996c9cc000b12"
     cluster="m3e9.0b9996c9cc000b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['03840e1a025cf7c0c1f931a9df8b7ed3','238ab63885757a39ffe04a5c40433edc','b6eeef952cc952b8c275cf29ae837d5a']"

   strings:
      $hex_string = { ad1c58a3c2aa80fc5539126b573fddbaf49707c500964ad5cc79316cb678730650a74aa47c7dc887b344ee2b46a0d784673b1037dbc77448e240146fb0e15a64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
