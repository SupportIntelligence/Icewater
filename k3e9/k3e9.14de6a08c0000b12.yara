
rule k3e9_14de6a08c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.14de6a08c0000b12"
     cluster="k3e9.14de6a08c0000b12"
     cluster_size="566"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bublik generickd upatre"
     md5_hashes="['000ba3b3a77a2d970823815ae8387a0b','0228367e4dd27bea96ec34229e4b6d9f','1bf7d54d228274997b6091c91ade5498']"

   strings:
      $hex_string = { 0552b466bc7a8d18100e1804e5ebaab80827e5e8883631dc11f0eeac71bc3521f065068fd8edb1ce49ce1c08165f8ec27d0eb10ce2cd0041bc5dc9eafcb85ce2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
