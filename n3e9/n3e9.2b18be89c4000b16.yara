
rule n3e9_2b18be89c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b18be89c4000b16"
     cluster="n3e9.2b18be89c4000b16"
     cluster_size="74"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler gdsda"
     md5_hashes="['043f6dcc98ad7cb0efd766bd5593bef3','076eda4223e0cfd45311a8080022c19e','290044bcbe17940cd0b45239cacf5220']"

   strings:
      $hex_string = { 0043006f00640065003a002000250064002e000a00250073001b0041002000570069006e003300320020004100500049002000660075006e006300740069006f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
