
rule k2319_39593ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39593ce9c8800b12"
     cluster="k2319.39593ce9c8800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1adc1887f6d7f5ebeff03a9753349b72b49ac5c2','a151a1b2554ec20fe6dede362b0e64ad11ef7e34','393327194b8808edc0d77693bcb2efee830bd966']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39593ce9c8800b12"

   strings:
      $hex_string = { 6e646566696e6564297b72657475726e20705b535d3b7d76617220523d28283134342e3545312c3078323141293e3134323f28312e33343145332c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
