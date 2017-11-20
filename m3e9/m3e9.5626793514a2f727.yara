
rule m3e9_5626793514a2f727
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5626793514a2f727"
     cluster="m3e9.5626793514a2f727"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob patched"
     md5_hashes="['4ad9efdf54e0a409889377337118851b','69cd1b3f563c4bdb964549eaf441862a','d68af861b16c9a4ec7df7f7c489192b2']"

   strings:
      $hex_string = { b5e5328a42988719f712b907bfc01c67eb857efb44a9e8aedb702cec54af5f57d9f075394db3ba7fa40c9e3f62994b9cb082a8634fbb41ac4c5df802c53091b7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
