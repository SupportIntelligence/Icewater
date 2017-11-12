
rule m3e9_4b33ad0a90f96b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4b33ad0a90f96b92"
     cluster="m3e9.4b33ad0a90f96b92"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler optimuminstaller"
     md5_hashes="['1e0b8bfbffd08c73354ba1c0041b4c4d','225fd8832800aecf06599493c2e030b5','f5a2eddbb850c5acf49f47450b46b66a']"

   strings:
      $hex_string = { 752be8510affff5353535353c70016000000e802f5feff83c414385dec74078b45e8836070fd33c0e950010000578b7d0c3bfb752be81e0affff5353535353c7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
