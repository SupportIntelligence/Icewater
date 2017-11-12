
rule m3e9_5942dc6251aad6f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5942dc6251aad6f2"
     cluster="m3e9.5942dc6251aad6f2"
     cluster_size="164"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef autorun"
     md5_hashes="['00652c7011317db9ebd5f7af91aec7b3','03e508d0fa80f124ce39e9cfd5b9998f','586e50a1b2a9b9fd83e2ee4d87466a4d']"

   strings:
      $hex_string = { fc0df538000000080800065400fca0f463fc0df539000000080800065400fca0f463fc0df53a000000080800065400fca0f463fc0df53b000000080800065400 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
