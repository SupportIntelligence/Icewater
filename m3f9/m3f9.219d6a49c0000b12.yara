
rule m3f9_219d6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.219d6a49c0000b12"
     cluster="m3f9.219d6a49c0000b12"
     cluster_size="1279"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="deepscan pwstealer scar"
     md5_hashes="['001be84f3fd71ff7fd4131100f79512a','003c9758466be16d44d64eea816e1f6f','03a100dec97840e0d58568952a4f9de5']"

   strings:
      $hex_string = { bfd117e0a465dc019fe4872667c3e92d1655fb6acf1a4d71da05c540a7a185c920a875c8f4a582c13014f61d356c283c0b66c0810e3e76aead9238b9dc6157ca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
