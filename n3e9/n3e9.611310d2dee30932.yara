
rule n3e9_611310d2dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.611310d2dee30932"
     cluster="n3e9.611310d2dee30932"
     cluster_size="37"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd bublik upatre"
     md5_hashes="['03a5f672d83cccee46ce3b79d09fc427','081c8c822e6bb5177903b81420a3a41b','8c359dae688015b125d6564dccf16de7']"

   strings:
      $hex_string = { bb640a0cf46fd81e87df771fc25ffd92a2cbfa34fb1423453d8fa8bd95a6ad996729c0177cdaae7126f153024fc1501344f5b26e65bec3b754cfb33b524338cc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
