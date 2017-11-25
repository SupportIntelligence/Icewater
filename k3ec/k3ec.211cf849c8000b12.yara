
rule k3ec_211cf849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.211cf849c8000b12"
     cluster="k3ec.211cf849c8000b12"
     cluster_size="443"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor darkkomet fynloski"
     md5_hashes="['000b8d7d865147b7c28b246259f026c0','005f01f0fa914ce8f7cb772746ec41af','083e643c510fb4022011059ef7a19d9f']"

   strings:
      $hex_string = { 4f532049643d227b31663637366337362d383065312d343233392d393562622d3833643066366430646137387d223e3c2f737570706f727465644f533e0d0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
