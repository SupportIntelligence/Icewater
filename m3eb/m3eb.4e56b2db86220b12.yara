
rule m3eb_4e56b2db86220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3eb.4e56b2db86220b12"
     cluster="m3eb.4e56b2db86220b12"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['121a4fc51eb6a360b3b6141b3752460e','477dda1d20952c0d3dfc458ce77cbdb1','f6c8856f6f79c98dab6a96dd825c6665']"

   strings:
      $hex_string = { 28715d1cc9afd6abe5189a0fa1450e889baa1be45ebd364273014fc7f3351a5075461c6599647e80a23ea6ea4b554112b1bebf208190dcf91d48e7169263279e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
