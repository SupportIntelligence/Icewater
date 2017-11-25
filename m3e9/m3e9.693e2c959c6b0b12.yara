
rule m3e9_693e2c959c6b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693e2c959c6b0b12"
     cluster="m3e9.693e2c959c6b0b12"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbobfus"
     md5_hashes="['0206d07c154c795637cb761b5a60e5e8','09f810cae67801a0e46784bc216d05ee','aa6b222f8886bc9ddce14032e137391d']"

   strings:
      $hex_string = { 0a0e13151e50515c5c5d688b8e8d8a7c69969795b5c6a0bb9fc3ccd9f8fffffffffaf9f1ad000000f2ffff65151f1e0f10121e22575c5d7a7d80a6abc8c8bbbb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
