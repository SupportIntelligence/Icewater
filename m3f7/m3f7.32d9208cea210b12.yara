
rule m3f7_32d9208cea210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.32d9208cea210b12"
     cluster="m3f7.32d9208cea210b12"
     cluster_size="88"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['02aa8038eaea942028a589fce805f80b','0578f4de1337ee06382d6e84e86c59c8','22d964aa2b8e0cfb68aa196d86dc8b91']"

   strings:
      $hex_string = { 31383233374446333432434631354236333741353638414639394230463444454335393142444132383030444632433546364543453933454241354438433430 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
