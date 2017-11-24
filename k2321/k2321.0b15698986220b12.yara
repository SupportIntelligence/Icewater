
rule k2321_0b15698986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b15698986220b12"
     cluster="k2321.0b15698986220b12"
     cluster_size="18"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email backdoor"
     md5_hashes="['14c8899ad03c65349862f9a1b949a505','16bff25d08465984e32dad1229db35fa','e36a31a28aa30bc8612694d43ace58e6']"

   strings:
      $hex_string = { 309b297e79f363aad858caadc0d4d745c703150d2e6685ce9057e3e183f712052439286b591eb56b6a113259a0b7af96a7bfa236e510fe522254a12f866dcb1d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
