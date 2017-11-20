
rule m3e9_693c265dc3a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693c265dc3a31912"
     cluster="m3e9.693c265dc3a31912"
     cluster_size="51"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi malicious"
     md5_hashes="['034ff49d737b9bbb3c6337783a9132b8','24e1c78103875bbf20fd252d1c27a889','b137768025703fae8807b2eabc9ea478']"

   strings:
      $hex_string = { 150a0e13151e50515c5c5d688b8e8d8a7c69969795b5c6a0bb9fc3ccd9f8fffffffffaf9f1ad000000f2ffff65151f1e0f10121e22575c5d7a7d80a6abc8c8bb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
