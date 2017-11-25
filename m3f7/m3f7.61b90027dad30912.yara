
rule m3f7_61b90027dad30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.61b90027dad30912"
     cluster="m3f7.61b90027dad30912"
     cluster_size="1992"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['000ca5bd52e0fa34d0dbd3e557e9bb14','00238a4c2d073f77150ff4e62e083f7c','018d244298ab60cf285f7f0735dca20b']"

   strings:
      $hex_string = { 31383233374446333432434631354236333741353638414639394230463444454335393142444132383030444632433546364543453933454241354438433430 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
