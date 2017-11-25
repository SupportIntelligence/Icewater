
rule n3e9_329ad14ed912e131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.329ad14ed912e131"
     cluster="n3e9.329ad14ed912e131"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="multiplug mplug nbqm"
     md5_hashes="['a12079ca2cd9e5992963c47d25a89f39','b4a5cf6d87de01cf3fdb0c0a3ed44ffc','c67e779a1b9cbbc8bd76631eeeab179d']"

   strings:
      $hex_string = { 3e383e0060030064000000bc30c03008312831483168318831a831c831e431e8310432083228324832543270329032b032d032f032fc32183324334033603380 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
