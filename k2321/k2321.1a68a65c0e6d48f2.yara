
rule k2321_1a68a65c0e6d48f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1a68a65c0e6d48f2"
     cluster="k2321.1a68a65c0e6d48f2"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['13eac97d5ea118dac4476433d6f119f3','76d82598e827c3fac28c84dfc5ab8519','e4201e7b063c11b9330e06abfb74ee7b']"

   strings:
      $hex_string = { 116e96bfa4c6c3c585f244482847f8a56cf1672efc5c0d1845f5826b97e7ad7da8f67033b57b16d50caeeefdbc3529362663c1cf3eff00ea045c23c23bfa512f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
