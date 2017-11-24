
rule m3e9_2b3917cefa630916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b3917cefa630916"
     cluster="m3e9.2b3917cefa630916"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup lethic kryptik"
     md5_hashes="['598064ce4e709c9eba763ab3fda01fd3','61bc3b89615c97215b5dc24cee09e400','d6ab1214b16b6d2b508766d43902f20e']"

   strings:
      $hex_string = { 627370e16fc82ed6b689d4d2dfcae911af6d5414469fa2743d5aebaa0324058b668ace98212c990ad3e2c2101ad188816025848c7806531964bb17bc3850b11e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
