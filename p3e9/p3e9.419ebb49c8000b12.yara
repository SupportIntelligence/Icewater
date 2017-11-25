
rule p3e9_419ebb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.419ebb49c8000b12"
     cluster="p3e9.419ebb49c8000b12"
     cluster_size="175"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock pubfii nabucur"
     md5_hashes="['0c7136fd1077e174796d9926e19cff44','11257b835c99321beeead6c783e242f4','51ecb4a874ff55de1607c096518200fc']"

   strings:
      $hex_string = { f3cdabfff0caa9ffedc7a8ffe9c3a5ffe6c0a3ffe2bca1ffdeb89fffdab49effd6b19bffd3ad99ffcfaa97ffcca696ffc9a494ffb17f73ff030303230b0b0b0b }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
