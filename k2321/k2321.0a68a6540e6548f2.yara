
rule k2321_0a68a6540e6548f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0a68a6540e6548f2"
     cluster="k2321.0a68a6540e6548f2"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['ba13d0804a153a3e91cd85ddeb4a25d8','bd8135145b0a2c8182fa65771c1ab67d','f3f4babb8c40f520d38be044896ec307']"

   strings:
      $hex_string = { 116e96bfa4c6c3c585f244482847f8a56cf1672efc5c0d1845f5826b97e7ad7da8f67033b57b16d50caeeefdbc3529362663c1cf3eff00ea045c23c23bfa512f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
