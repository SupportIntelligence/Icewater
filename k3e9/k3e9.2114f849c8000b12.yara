
rule k3e9_2114f849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2114f849c8000b12"
     cluster="k3e9.2114f849c8000b12"
     cluster_size="586"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jaik backdoor darkkomet"
     md5_hashes="['000e9dda9f00082c800a7a2f26527cb0','00b8fa86ca880ffee0c576adcc5e4737','07cae0f09ab0f45433f1b4376f0526df']"

   strings:
      $hex_string = { 4f532049643d227b31663637366337362d383065312d343233392d393562622d3833643066366430646137387d223e3c2f737570706f727465644f533e0d0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
